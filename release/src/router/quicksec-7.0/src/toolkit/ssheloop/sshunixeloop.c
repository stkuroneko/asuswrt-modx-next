/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   The implementation of the generic event loop.
*/

#include "sshincludes.h"
#include "sshtimeoutsi.h"
#include "ssheloop.h"
#include "sshglobals.h"

#ifdef HAVE_SIGNAL
#include <signal.h>
#endif /* HAVE_SIGNAL */

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif /* HAVE_SYS_POLL_H */





#include "sshadt.h"
#include "sshadt_map.h"

#define SSH_DEBUG_MODULE "SshEventLoop"

#define BILLION 1000000000L
#define MILLION 1000000L
#define THOUSAND 1000L

#define SSH_TIMEOUT_MAX_SECONDS BILLION

/* Determine whether to use poll() or select() */

#ifdef USE_POLL
#undef USE_POLL
#endif /* USE_POLL */

#ifdef USE_SELECT
#undef USE_SELECT
#endif /* USE_SELECT */

#ifdef HAVE_POLL
#ifdef ENABLE_SELECT
#ifdef HAVE_SELECT
#define USE_SELECT
#else
#define USE_POLL
#endif /* HAVE_SELECT */
#else
#define USE_POLL
#endif /* ENABLE_SELECT */
#else
#ifdef HAVE_SELECT
#define USE_SELECT
#endif /* HAVE_SELECT */
#endif /* HAVE_POLL */

/* The USE_POLL and USE_SELECT are mutually exclusive */

#ifndef USE_POLL
#ifndef USE_SELECT
#error Can not compile without select or poll
#endif
#endif

/* Set defaults according to this choice */

#ifdef USE_SELECT
#ifdef FD_SETSIZE
#define SSH_ELOOP_INITIAL_REQS_ARRAY_SIZE (FD_SETSIZE)
#else
#define SSH_ELOOP_INITIAL_REQS_ARRAY_SIZE 1024
#endif /* FD_SETSIZE */
#else
#define SSH_ELOOP_INITIAL_REQS_ARRAY_SIZE 16
#endif /* USE_SELECT */


#define SSH_ELOOP_REQS_ARRAY_SIZE_STEP    16

#define SSH_ELOOP_TIMEOUT_FREELIST_INITIAL_SIZE 100

/* The timeouts are kept in a priority heap. The file descriptors are
   kept in an array indexed by the descriptors. Signals are indexed by
   the signal numbers. Signals are put into queue too. */

#ifdef HAVE_SIGNAL

#ifndef NSIG
#define NSIG 32
#endif

typedef struct SshEloopSignalRec
{
    SshSignalCallback callback;
    void *context;
} *SshEloopSignal, SshEloopSignalStruct;
#endif /* HAVE_SIGNAL */

typedef struct SshEloopIORec
{
    int fd;
    bool was_nonblocking;
    SshIoCallback callback;
    void *context;
    struct SshEloopIORec *next;
    bool killed;
    int request;
#ifdef USE_POLL
    int poll_idx;
#endif /* USE_POLL */
} *SshEloopIO, SshEloopIOStruct;

typedef struct SshEloopRec
{
    bool running;

    SshEloopIO io_records;
    SshEloopIO io_records_tail;
    SshEloopIO *fd_to_record_map;
    int fd_map_size;
    SshTimeoutContainerStruct to;
    struct timeval *select_timeout_ptr;
    bool in_select;
    bool is_clean_necessary;
    bool is_pollcache_invalid;

    /* Freelist of SshTimeoutStruct object used in calls
       to ssh_[x]timeout_register.  */
    SshTimeout timeout_freelist;

#ifdef HAVE_SIGNAL
    sigset_t used_signals;
    SshEloopSignal signal_records;
    bool fired_signals[NSIG];
    bool signal_fired;
#endif /* HAVE_SIGNAL */

#ifdef USE_POLL
    struct pollfd *pfds;
    unsigned int pfd_size;
#endif /* USE_POLL */

    struct timeval select_timeout_no_wait;
}
*SshEloop, SshEloopStruct;

SSH_GLOBAL_DECLARE(SshEloopStruct, ssheloop);
#define ssheloop SSH_GLOBAL_USE_INIT(ssheloop)
SSH_GLOBAL_DEFINE_INIT(SshEloopStruct, ssheloop) = {};

void timeout_freelist_alloc(SshEloop eloop)
{
    void *item;
    void *list = NULL;
    int i;

    for (i = 0; i < SSH_ELOOP_TIMEOUT_FREELIST_INITIAL_SIZE; i++)
    {
        item = ssh_xcalloc(1, sizeof(SshTimeoutStruct));
        *((void **)item) = list;
        list = item;
    }
    eloop->timeout_freelist = list;
}

void timeout_freelist_free(SshEloop eloop)
{
    void *list = eloop->timeout_freelist;
    void *next;

    SSH_DEBUG(SSH_D_HIGHOK, ("Freeing timeout structure freelist"));

    while (list)
    {
        next = *((void **)list);
        ssh_xfree(list);
        list = next;
    }
}

#define TIMEOUT_FREELIST_GET(item, list)                \
do                                                      \
  {                                                     \
    (item) = (void *)(list);                            \
    if (list)                                           \
      (list) = *((void **)(item));                      \
  }                                                     \
while (0)

#define TIMEOUT_FREELIST_PUT(item, list)                \
do                                                      \
  {                                                     \
    *((void **)(item)) = (list);                        \
    (list) = (void *)(item);                            \
  }                                                     \
while (0)


/* Initializes the event loop.  This must be called before any other
   event loop, timeout, or stream function.  The IO records list
   contains no items.  The fd_to_record_map array contains initially
   SSH_ELOOP_INITIAL_REQS_ARRAY_SIZE items. The array is mallocated
   here. The signal records array contains exactly NSIG items. The
   size of the array never changes, contrary to the requests
   array. Timeouts records list contains no items, neither the list of
   fired signals. */

void ssh_event_loop_initialize(void)
{
    ssheloop.select_timeout_no_wait.tv_sec = 0L;
    ssheloop.select_timeout_no_wait.tv_usec = 0L;

#ifdef HAVE_SIGNAL
    sigemptyset(&ssheloop.used_signals);
    ssheloop.signal_records = ssh_xcalloc(NSIG, sizeof(SshEloopSignalStruct));
#endif /* HAVE_SIGNAL */

    ssh_timeout_container_initialize(&ssheloop.to);

    ssheloop.fd_map_size = SSH_ELOOP_INITIAL_REQS_ARRAY_SIZE;
    ssheloop.fd_to_record_map =
      ssh_xcalloc(1, sizeof(ssheloop.fd_to_record_map[0])
                  * ssheloop.fd_map_size);
#ifdef USE_POLL
    ssheloop.pfds = ssh_xmalloc(sizeof(ssheloop.pfds[0])
                               * ssheloop.fd_map_size);
#endif /* USE_POLL */

    timeout_freelist_alloc(&ssheloop);

    ssheloop.running = false;

    SSH_DEBUG(SSH_D_HIGHOK, ("Initialized the event loop."));
}

/* Abort the event loop. This causes the event loop to exit before
   the next select(). */

void ssh_event_loop_abort(void)
{
    if (ssheloop.running == true)
      ssheloop.running = false;
}

void ssh_event_loop_lock(void)
{
    return;
}

void ssh_event_loop_unlock(void)
{
    return;
}

static void ssh_event_loop_delete_all_fds(void)
{
    SshEloopIO temp;

    ssheloop.is_pollcache_invalid = true;
    ssheloop.is_clean_necessary = true;

    while (ssheloop.io_records != NULL)
    {
        temp = ssheloop.io_records;
        ssheloop.io_records = temp->next;
        ssh_free(temp);
    }
    ssheloop.io_records = NULL;
    ssheloop.io_records_tail = NULL;
}

#ifdef HAVE_SIGNAL
static void ssh_event_loop_delete_all_signals(void)
{
    int sig;

    for (sig = 1; sig <= NSIG; sig++)
    {
        if (sigismember((&(ssheloop.used_signals)), sig))
          ssh_unregister_signal(sig);
    }
}
#endif /* HAVE_SIGNAL */

/* Uninitialize the event loop after it has returned.
   Delete all timeouts etc. left and free the structures. */

void ssh_event_loop_uninitialize(void)
{
    ssh_cancel_timeouts(SSH_ALL_CALLBACKS, SSH_ALL_CONTEXTS);

    ssh_timeout_container_uninitialize(&ssheloop.to);

    ssh_event_loop_delete_all_fds();

#ifdef HAVE_SIGNAL
    ssh_event_loop_delete_all_signals();
#endif /* HAVE_SIGNAL */

    ssh_free(ssheloop.fd_to_record_map);

    timeout_freelist_free(&ssheloop);

#ifdef USE_POLL
    ssh_free(ssheloop.pfds);
#endif /* USE_POLL */

#ifdef HAVE_SIGNAL
    ssh_free(ssheloop.signal_records);
#endif /* HAVE_SIGNAL */

    SSH_DEBUG(SSH_D_HIGHOK, ("Uninitialized the event loop."));
}

/* The signal handler. Insert a new fired signal structure to the
   list of fired signals. Block signals until the insertion has
   finished so that other caught signals don't mess the list up. */

#ifdef HAVE_SIGNAL
static RETSIGTYPE ssh_event_loop_signal_handler(int sig)
{
    sigset_t old_set;

    SSH_ASSERT(sig > 0 && sig <= NSIG);

    /* Signals are blocked during the execution of this call. */
    sigprocmask(SIG_BLOCK, &ssheloop.used_signals, &old_set);

    if (ssheloop.in_select)
    {
        /* We were in select(), deliver the callback immediately. */
        if (ssheloop.signal_records[sig - 1].callback)
          (*ssheloop.signal_records[sig - 1].callback)(sig,
             ssheloop.signal_records[sig - 1].context);
    }
    else
    {
        /* We are currently processing a callback; deliver the signal callback
           when the current callback returns. */
        ssheloop.signal_fired = true;
        ssheloop.fired_signals[sig - 1] = true;
    }

    sigprocmask(SIG_SETMASK, &old_set, NULL);
}
#endif /* HAVE_SIGNAL */

/*****************************************************************************
 * Timeouts
 */

/* Get current time. This system also handles backward jumps at the
   wall clock time (e.g. current time being less than reference time
   records at previous call to this routine. */
static void
ssh_eloop_gettime(
        struct timespec *tp)
{
    if (clock_gettime(CLOCK_MONOTONIC, tp) < 0)
    {
        /*
          clock_gettime can only fail, for unsupported clock id
          (CLOCK_MONOTONIC), or invalid pointer i.e. &monotonic_time.
         */
        SSH_NOTREACHED;
    }
}

/* Compare two struct timespecs. */
static int
ssh_event_loop_compare_time(struct timespec *first,
                            struct timespec *second)
{
    return
      (first->tv_sec  < second->tv_sec)  ? -1 :
      (first->tv_sec  > second->tv_sec)  ?  1 :
      (first->tv_nsec < second->tv_nsec) ? -1 :
      (first->tv_nsec > second->tv_nsec) ?  1 : 0;
}

/* Convert relative timeout to absolute firing time. */
static void
ssh_eloop_convert_relative_to_absolute(
        long seconds,
        long nanoseconds,
        struct timespec *timespec)
{
    SSH_ASSERT(nanoseconds >= 0 && nanoseconds < BILLION);

    ssh_eloop_gettime(timespec);

    timespec->tv_sec += seconds;
    timespec->tv_nsec += nanoseconds;

    if (timespec->tv_nsec >= BILLION)
    {
        timespec->tv_nsec -= BILLION;
        timespec->tv_sec  += 1L;
    }
}

SshTimeout
ssh_register_timeout_internal(
        SshTimeout state,
        long seconds,
        long microseconds,
        SshTimeoutCallback callback,
        void *context)
{
    SshTimeout created, p;
    SshADTHandle handle;
    long nanoseconds;


    SSH_DEBUG(SSH_D_MIDOK,
              ("timeout to be registered at %ld:%ld",
               seconds,
               microseconds));

    created = state;
    if (seconds > SSH_TIMEOUT_MAX_SECONDS)
    {
        seconds = SSH_TIMEOUT_MAX_SECONDS;
        nanoseconds = 0;
    }
    else
    {
        seconds += microseconds / MILLION;
        nanoseconds = (microseconds % MILLION) * THOUSAND;
    }

    /* Convert to absolute time and initialize timeout record. */
    ssh_eloop_convert_relative_to_absolute(
            seconds,
            nanoseconds,
            &created->firing_time);

    created->callback = callback;
    created->context = context;
    created->identifier = ssheloop.to.next_identifier++;

    ssh_adt_insert(ssheloop.to.map_by_identifier, created);
    ssh_adt_insert(ssheloop.to.ph_by_firing_time, created);

    if ((handle =
         ssh_adt_get_handle_to_equal(ssheloop.to.map_by_context, created))
        != SSH_ADT_INVALID)
    {
        p = ssh_adt_get(ssheloop.to.map_by_context, handle);
        created->next = p->next;
        created->prev = p;
        if (p->next)
          p->next->prev = created;
        p->next       = created;
    }
    else
    {
        created->next = NULL;
        created->prev = NULL;
        ssh_adt_insert(ssheloop.to.map_by_context, created);
    }

    SSH_DEBUG(SSH_D_MIDOK,
              ("timeout %qd at %ld:%ld",
               created->identifier,
               created->firing_time.tv_sec,
               created->firing_time.tv_nsec));

    return created;
}

SshTimeout
ssh_xregister_timeout(long seconds,
                      long microseconds,
                      SshTimeoutCallback callback,
                      void *context)
{
    SshTimeout created;

    TIMEOUT_FREELIST_GET(created, ssheloop.timeout_freelist);

    if (created == NULL)
    {
        SSH_DEBUG(SSH_D_HIGHOK,
                  ("Timeout freelist empty, allocating new entry"));
        created = ssh_xmalloc(sizeof(*created));
    }

    memset(created, 0, sizeof(*created));

    created->is_dynamic = true;
    return ssh_register_timeout_internal(created, seconds, microseconds,
                                         callback, context);
}


void
ssh_timeout_time_left(
        SshTimeout timeout,
        long *seconds_p,
        long *microseconds_p)
{
    struct timespec timespec;
    long seconds;
    long nanoseconds;

    ssh_eloop_gettime(&timespec);

    seconds = timeout->firing_time.tv_sec - timespec.tv_sec;
    nanoseconds = timeout->firing_time.tv_nsec - timespec.tv_nsec;

    if (seconds < 0)
    {
        seconds = 0;
        nanoseconds = 0;
    }

    if (nanoseconds < 0L)
    {
        if (seconds > 0)
        {
            nanoseconds += BILLION;
            --seconds;
        }
        else
        {
            nanoseconds = 0;
        }
    }

    if (microseconds_p != NULL)
    {
        *microseconds_p = nanoseconds / 1000L;
    }

    if (seconds_p != NULL)
    {
        *seconds_p = seconds;
    }
}

SshTimeout
ssh_register_timeout(SshTimeout state,
                     long seconds,
                     long microseconds,
                     SshTimeoutCallback callback,
                     void *context)
{
    if (state != NULL)
    {
        memset(state, 0, sizeof(*state));
        state->is_dynamic = false;
    }
    else
    {
        /* get from freelist */

        TIMEOUT_FREELIST_GET(state, ssheloop.timeout_freelist);
        if (state == NULL)
        {
            state = ssh_malloc(sizeof(*state));
            if (state == NULL)
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("Insufficient memory to instantiate timeout!"));
                return NULL;
            }
        }
        memset(state, 0, sizeof(*state));
        state->is_dynamic = true;
    }

    return ssh_register_timeout_internal(state, seconds, microseconds,
                                         callback, context);
}

void
ssh_cancel_timeout(SshTimeout timeout)
{
    SshTimeout p;
    SshADTHandle mh, ph, cmh;

    if (timeout == NULL)
      return;

    if ((mh =
         ssh_adt_get_handle_to_equal(ssheloop.to.map_by_identifier, timeout))
        != SSH_ADT_INVALID)
    {
        p = ssh_adt_get(ssheloop.to.map_by_identifier, mh);
        SSH_ASSERT(timeout == p);

        SSH_DEBUG(SSH_D_MIDOK, ("cancelled %qd", p->identifier));

        ph = &p->adt_ft_ph_hdr;

        ssh_adt_detach(ssheloop.to.ph_by_firing_time, ph);
        ssh_adt_detach(ssheloop.to.map_by_identifier, mh);

        if (p->prev == NULL)
        {
            cmh = &p->adt_ctx_map_hdr;
            ssh_adt_detach(ssheloop.to.map_by_context, cmh);
            if (p->next)
            {
                p->next->prev = NULL;
                ssh_adt_insert(ssheloop.to.map_by_context, p->next);
            }
        }
        else
        {
            p->prev->next = p->next;
            if (p->next)
              p->next->prev = p->prev;
        }

        if (p->is_dynamic)
          TIMEOUT_FREELIST_PUT(p, ssheloop.timeout_freelist);
        else
          memset(p, 0, sizeof(*p));

        return;
    }
}

/* Cancel all timeouts that call `callback' with context `context'.
   SSH_ALL_CALLBACKS and SSH_ALL_CONTEXTS can be used as wildcards. */
void ssh_cancel_timeouts(SshTimeoutCallback callback, void *context)
{
    SshADTHandle nmh, mh, cmh;
    SshTimeoutStruct probe;

    if (context != SSH_ALL_CONTEXTS)
    {
        /* Cancel with given context. */
        probe.context = context;
        if ((cmh =
             ssh_adt_get_handle_to_equal(ssheloop.to.map_by_context, &probe))
            != SSH_ADT_INVALID)
        {
            ssh_to_remove_from_contextmap(&ssheloop.to,
                                          callback, context, cmh);
        }
    }
    else
    {
        /* Cancel with wildcard context. Enumerates context map and
           traverses its lists. */
        for (mh = ssh_adt_enumerate_start(ssheloop.to.map_by_context);
             mh != SSH_ADT_INVALID;
             mh = nmh)
        {
            nmh = ssh_adt_enumerate_next(ssheloop.to.map_by_context, mh);
            ssh_to_remove_from_contextmap(&ssheloop.to, callback, context, mh);
        }
    }
}

#ifdef HAVE_SIGNAL
/*****************************************************************************
 * Signals
 */

/* Register a new signal. Add the signal action with the sigaction()
   system call. Also insert the callback and context information to
   the static array of signal callbacks, indexed by the signal
   number. */

void ssh_register_signal(int sig, SshSignalCallback callback,
                         void *context)
{
    struct sigaction action;
    sigset_t mask, old_mask;

    memset(&action, 0, sizeof(action));

    if (sig <= 0 || sig > NSIG)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Registering bad signal %d ignored.", sig));
        return;
    }

    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);

    sigaddset(&(ssheloop.used_signals), sig);
    ssheloop.signal_records[sig - 1].callback = callback;
    ssheloop.signal_records[sig - 1].context = context;
    action.sa_handler = ssh_event_loop_signal_handler;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    sigaction(sig, &action, NULL);

    sigprocmask(SIG_SETMASK, &old_mask, (sigset_t *) NULL);

    SSH_DEBUG(SSH_D_MIDOK, ("Registered signal %d.", sig));
}

/* Unregister a signal. Set the signal action to its system default
   with the sigaction() system call. Also set the callback and context
   information of the signal to NULLs. */

void ssh_unregister_signal(int sig)
{
    struct sigaction action;
    sigset_t mask, old_mask;
    bool previously_fired;

    memset(&action, 0, sizeof(action));

    if (sig <= 0 || sig > NSIG)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Unregistering bad signal %d ignored.", sig));
        return;
    }
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);

    action.sa_handler = SIG_DFL;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    sigaction(sig, &action, NULL);
    sigdelset(&ssheloop.used_signals, sig);

    /* Save the signal status. */
    previously_fired = ssheloop.fired_signals[sig - 1];
    ssheloop.fired_signals[sig - 1] = false;

    ssheloop.signal_records[sig - 1].callback = NULL_FNPTR;
    ssheloop.signal_records[sig - 1].context = NULL;

    sigprocmask(SIG_SETMASK, &old_mask, (sigset_t *) NULL);

    if (previously_fired)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Reissuing signal "
                   "for which callback was not yet delivered."));
        kill(getpid(), sig);
    }

    SSH_DEBUG(SSH_D_MIDOK, ("Unregistered signal %d.", sig));
}
#endif /* HAVE_SIGNAL */

/*****************************************************************************
 * File IO
 */

/* Register a file descriptor. Create a structure and add it to the
   beginning of the list of IO records. Arrays are expanded if
   necessary. */
bool
ssh_io_register_fd(SshIOHandle fd, SshIoCallback callback, void *context)
{
    SshEloopIO created;
#ifdef USE_POLL
    struct pollfd *pfds;
    int nrequests;
    SshEloopIO *requests;
#endif /* USE_POLL */

    SSH_DEBUG(SSH_D_NICETOKNOW, ("register fd=%d", fd));

    if (fd < ssheloop.fd_map_size && ssheloop.fd_to_record_map[fd] != NULL)
    {
#ifdef DEBUG_LIGHT
        ssh_fatal(
                "ssh_io_register_fd: Attempt to register fd %d multiple times",
                fd);
#endif /* DEBUG_LIGHT */
        return false;
    }

    /* First make sure a sufficient amount of store exists. */

#ifdef USE_POLL
    requests = NULL;
    pfds = NULL;
#endif /* USE_POLL */

    created = ssh_malloc(sizeof(*created));

    if (created == NULL)
      goto fail;

    if (fd >= ssheloop.fd_map_size)
    {
#ifdef USE_SELECT
        SSH_DEBUG(SSH_D_FAIL,
                  ("Can not register file descriptor %d (fd_set limit %d)",
                   fd,ssheloop.fd_map_size));
        return false;
#endif /* USE_SELECT */

#ifdef USE_POLL
        nrequests = ssheloop.fd_map_size;

        nrequests += SSH_ELOOP_REQS_ARRAY_SIZE_STEP;

        if (fd >= nrequests)
          nrequests = fd +1;

        requests =
          ssh_realloc(ssheloop.fd_to_record_map,
                      ssheloop.fd_map_size
                      * sizeof(ssheloop.fd_to_record_map[0]),
                      nrequests
                      * sizeof(ssheloop.fd_to_record_map[0]));

        if (requests == NULL)
          goto fail;

        memset(&requests[ssheloop.fd_map_size], 0,
               sizeof(ssheloop.fd_to_record_map[0])
               * (nrequests - ssheloop.fd_map_size));

        pfds = ssh_realloc(ssheloop.pfds,
                           ssheloop.fd_map_size
                           * sizeof(ssheloop.pfds[0]),
                           nrequests
                           * sizeof(ssheloop.pfds[0]));

        if (pfds == NULL)
          goto fail;

        ssheloop.pfds = pfds;
        pfds = NULL;

        ssheloop.fd_map_size = nrequests;
        ssheloop.fd_to_record_map = requests;
        requests = NULL;
#endif /* USE_POLL */
    }

    /* Then initialize the state pertaining to the file descriptor */
    created->callback = callback;
    created->context = context;
    created->fd = fd;
    created->killed = false;
    created->request = 0;
    created->was_nonblocking =



      (fcntl(fd, F_GETFL, 0) & (O_NONBLOCK|O_NDELAY)) != 0;








    /* Make the file descriptor use non-blocking I/O. */
#  if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
        (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#  else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
        (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NDELAY);
#  endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */


    SSH_HEAVY_DEBUG(99, ("fd %d is %sin non-blocking mode.", fd,
                         (fcntl(fd, F_GETFL, 0) & (O_NONBLOCK|O_NDELAY)) != 0 ?
                         "" : "not "));

    /* Add the newly created structure to the END of the list. */
    created->next = NULL;
    if (ssheloop.io_records_tail)
      ssheloop.io_records_tail->next = created;
    else
      ssheloop.io_records = created;
    ssheloop.io_records_tail = created;

    ssheloop.fd_to_record_map[created->fd] = created;
#ifdef USE_POLL
    created->poll_idx = -1;
#endif /* USE_POLL */

    SSH_DEBUG(SSH_D_MIDOK, ("Registered file descriptor %d.", fd));
    return true;
   fail:


    if (created != NULL)
      ssh_free(created);

#ifdef USE_POLL
    if (requests != NULL)
      ssh_free(requests);


#endif /* USE_POLL */

    return false;
}

void
ssh_io_xregister_fd(SshIOHandle fd, SshIoCallback callback, void *context)
{
    if (ssh_io_register_fd(fd, callback,context) == false)
      ssh_fatal(
              "ssh_io_register_fd failed, could not register file descriptor");
}

/* Unregister a file descriptor. */

void ssh_io_unregister_fd(SshIOHandle fd, bool keep_nonblocking)
{
    SshEloopIO item;

    SSH_DEBUG(SSH_D_NICETOKNOW, ("unregister fd=%d", fd));

    ssheloop.is_pollcache_invalid = true;
    ssheloop.is_clean_necessary = true;

    item = ssheloop.fd_to_record_map[fd];
    if (item != NULL && item->killed == false)
    {
        SSH_ASSERT(item->fd == fd);

        if (!item->was_nonblocking && !keep_nonblocking)
        {



#  if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
            (void)fcntl(item->fd, F_SETFL,
                        fcntl(item->fd, F_GETFL, 0) & ~O_NONBLOCK);
#  else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
            (void)fcntl(item->fd, F_SETFL,
                        fcntl(item->fd, F_GETFL, 0) & ~O_NDELAY);
#  endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */

        }
        SSH_ASSERT(ssheloop.fd_to_record_map[item->fd] == item);
        ssheloop.fd_to_record_map[item->fd] = NULL;
        item->killed = true;
        SSH_DEBUG(SSH_D_MIDOK,
                  ("Killed the file descriptor %d, waiting for removal",
                   fd));
        return;
    }
    /* File descriptor was not found. */
    ssh_warning("ssh_io_unregister_fd: file descriptor %d was not found.", fd);
#ifdef DEBUG_LIGHT
    ssh_fatal("ssh_io_unregister_fd: file descriptor %d was not found.", fd);
#endif /* DEBUG_LIGHT */
}

/* Set the IO request(s) for a file descriptor. The file descriptor
   must have been registered previously to the event loop; otherwise
   the requests table might have less items than `fd'.
   ssh_fatal() is called if this happens. */

void ssh_io_set_fd_request(SshIOHandle fd, unsigned int request)
{
    SshEloopIO iorec;

    if (fd >= ssheloop.fd_map_size)
    {
        ssh_fatal("File descriptor %d exceeded the array size in "
                  "ssh_io_set_fd_request.",
                  fd);
    }

    iorec = ssheloop.fd_to_record_map[fd];
    SSH_ASSERT(iorec != NULL);
    SSH_ASSERT(iorec->fd == fd);

    iorec->request = request;

#ifdef USE_POLL
    if (ssheloop.is_pollcache_invalid == false && iorec->poll_idx != -1
        && (iorec->request & (SSH_IO_READ|SSH_IO_WRITE)))
    {
        SSH_DEBUG(SSH_D_MY,
                  ("optimized set fd=%d request=0x%08x", fd, request));

        SSH_ASSERT(ssheloop.pfds[iorec->poll_idx].fd == iorec->fd);

        ssheloop.pfds[iorec->poll_idx].events = 0;

        if (iorec->request & SSH_IO_READ)
          ssheloop.pfds[iorec->poll_idx].events |= POLLIN | POLLPRI;

        if (iorec->request & SSH_IO_WRITE)
          ssheloop.pfds[iorec->poll_idx].events |= POLLOUT;
    }
    else
#endif /* USE_POLL */
    {
        SSH_DEBUG(SSH_D_MY, ("invalidating set fd=%d request=0x%08x",
                             fd, request));
        ssheloop.is_pollcache_invalid = true;
    }
}

static void
ssh_timeout_time_left_timeval(
        SshTimeout timeout,
        struct timeval *timeval_left_p)
{
    long seconds;
    long microseconds;

    ssh_timeout_time_left(timeout, &seconds, &microseconds);

    timeval_left_p->tv_sec = seconds;
    timeval_left_p->tv_usec = microseconds;
}


/*****************************************************************************
 * Run the event loop.
 */
static void
ssh_event_loop_clean_fds(void)
{
    SshEloopIO iorec_temp, iorec_prev;
    SshEloopIO *iorec_ptr;

    if (ssheloop.is_clean_necessary == false)
      return;

    SSH_DEBUG(SSH_D_NICETOKNOW, ("clean fds!"));

    iorec_temp = ssheloop.io_records;
    iorec_ptr = &(ssheloop.io_records);
    iorec_prev = NULL;

    while (iorec_temp != NULL)
    {
        if (iorec_temp->killed == true)
        {
            SSH_DEBUG(SSH_D_MIDOK, ("Removed a killed IO callback."));
            /* First set the pointer to point to the next item in the list. */

            *iorec_ptr = iorec_temp->next;
            if (iorec_temp->next == NULL)
              ssheloop.io_records_tail = iorec_prev;

            /* Then free the killed structure. */
            ssh_free(iorec_temp);

            /* Finally set the iteration pointer to the next item
               in the list. */
            iorec_temp = *iorec_ptr;
        }
        else
        {
            iorec_ptr = &(iorec_temp->next);
            iorec_prev = iorec_temp;
            iorec_temp = iorec_temp->next;
        }
    }
    ssheloop.is_clean_necessary = false;
}

void
ssh_event_loop_run(void)
{
    struct timespec current_time;
    struct timeval select_timeout;
    SshADTHandle ph;
    SshEloopIO iorec_temp;
    bool done_something;
    unsigned int nfds;
    int poll_return_value;
#ifdef USE_POLL
    int poll_nopoll_counter;
    int poll_timeout;
    int idx;
#endif /* USE_POLL */
#ifdef USE_SELECT
    fd_set readfds, writefds;
    int max_fd;
#endif /* USE_SELECT */

#ifdef HAVE_SIGNAL
    sigset_t old_set;
#endif /* HAVE_SIGNAL */

    SSH_DEBUG(SSH_D_HIGHOK, ("Starting the event loop."));

    ssheloop.running = true;
    ssheloop.is_clean_necessary = true;
    ssheloop.is_pollcache_invalid = true;
    ssheloop.in_select = false;

#ifdef USE_POLL
    poll_nopoll_counter = 0;
#endif /* USE_POLL */

    while (1)
    {
        done_something = false;

#ifdef HAVE_SIGNAL
        /* Handle signals. */
        while (ssheloop.signal_fired)
        {
            int i;

            /* We don't want to get signals during this because we're
               modifying the signals list. */
            sigprocmask(SIG_BLOCK, &ssheloop.used_signals, &old_set);
            for (i = 1; i <= NSIG; i++)
            {
                if (ssheloop.fired_signals[i - 1])
                {
                    ssheloop.fired_signals[i - 1] = false;

                    SSH_DEBUG(SSH_D_MIDOK, ("Calling a signal handler."));

                    if (ssheloop.signal_records[i - 1].callback)
                    {
                        (*ssheloop.signal_records[i - 1].callback)(
                                i,
                                ssheloop.signal_records[i - 1].context);
                    }

                    done_something = true;
                }
            }
            ssheloop.signal_fired = false;

            /* Turn the mask off so that signals that have arrived during
               the iteration get into the queue. Then start the iteration
               again if the queue is not empty. */





            sigprocmask(SIG_SETMASK, &old_set, NULL);
        }
#endif /* HAVE_SIGNAL */

        ssheloop.select_timeout_ptr = NULL;

        /* Get current time */
        ssh_eloop_gettime(&current_time);

        /* If there are any timeouts to be fired fire them now.  If
           there are any timeouts waiting set the timeout of the
           select() call to match the earliest of the timeouts. */
        while (1)
        {
            SshTimeout firing_timeout;
            SshTimeoutCallback callback;
            void *callback_context;

            if ((ph = ssh_adt_enumerate_start(ssheloop.to.ph_by_firing_time))
                == SSH_ADT_INVALID)
                break;

            firing_timeout = ssh_adt_get(ssheloop.to.ph_by_firing_time, ph);

            if (ssh_event_loop_compare_time(
                        &firing_timeout->firing_time,
                        &current_time)
                > 0)
            {
                break;
            }

            callback = firing_timeout->callback;
            callback_context = firing_timeout->context;

            SSH_DEBUG(SSH_D_MIDOK, ("firing timeout %qd",
                                    firing_timeout->identifier));

            ssh_cancel_timeout(firing_timeout);

            if (callback)
            {
                (*callback)(callback_context);
            }
            done_something = true;
        }

        /* Determine the amount of time until the next timeout.  This
           can be in the past, because we run expire queue only once. */

        if ((ph = ssh_adt_enumerate_start(ssheloop.to.ph_by_firing_time))
            != SSH_ADT_INVALID)
        {
            SshTimeout next_timeout;

            next_timeout = ssh_adt_get(ssheloop.to.ph_by_firing_time, ph);

            ssh_timeout_time_left_timeval(next_timeout, &select_timeout);

            ssheloop.select_timeout_ptr = &select_timeout;
            SSH_DEBUG(SSH_D_LOWOK,
                      ("Select/Poll timeout: from %ld, %ld seconds, %ld usec.",
                       next_timeout->identifier,
                       ssheloop.select_timeout_ptr->tv_sec,
                       ssheloop.select_timeout_ptr->tv_usec));
        }

#ifdef USE_SELECT
        max_fd = -1;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
#endif /* USE_SELECT */
        /* Remove killed filedescriptors */
        ssh_event_loop_clean_fds();
        nfds = 0;

        iorec_temp = ssheloop.io_records;
#ifdef USE_POLL
        if (ssheloop.is_pollcache_invalid == true)
        {
            SSH_DEBUG(SSH_D_MY, ("poll cache has been invalidated!"));
#endif /* USE_POLL */
            while (iorec_temp != NULL)
            {
                SSH_ASSERT(iorec_temp->killed == false);

                if ((iorec_temp->request & (SSH_IO_READ | SSH_IO_WRITE)) != 0)
                {
#ifdef USE_POLL
                    ssheloop.pfds[nfds].fd = iorec_temp->fd;
                    ssheloop.pfds[nfds].events = 0;;
                    ssheloop.pfds[nfds].revents = 0;

                    if (iorec_temp->request & SSH_IO_READ)
                        ssheloop.pfds[nfds].events |= POLLIN | POLLPRI;

                    if (iorec_temp->request & SSH_IO_WRITE)
                        ssheloop.pfds[nfds].events |= POLLOUT;

                    iorec_temp->poll_idx = nfds;

#else /* USE_POLL */
                    if (iorec_temp->request & SSH_IO_READ)
                        FD_SET(iorec_temp->fd, &readfds);

                    if (iorec_temp->request & SSH_IO_WRITE)
                        FD_SET(iorec_temp->fd, &writefds);

                    if (max_fd < iorec_temp->fd)
                        max_fd = iorec_temp->fd;
#endif /* not USE_POLL */
                    nfds++;
                }
#ifdef USE_POLL
                else
                {
                    iorec_temp->poll_idx = -1;
                }
#endif /* USE_POLL */
                iorec_temp = iorec_temp->next;
            }
#ifdef USE_POLL
            ssheloop.pfd_size = nfds;
            ssheloop.is_pollcache_invalid = false;
        }
        else
            nfds = ssheloop.pfd_size;
#endif /* USE_POLL */

        if (nfds < 1 && ssheloop.select_timeout_ptr == NULL
            && done_something == false)
            break;

        /* Exit now if the event loop has been aborted. */
        if (!ssheloop.running)
            break;

        if (ssheloop.select_timeout_ptr != NULL &&
            ssheloop.select_timeout_ptr->tv_sec == 0 &&
            ssheloop.select_timeout_ptr->tv_usec != 0)
            SSH_DEBUG(SSH_D_LOWOK,
                      ("select/poll timeout: %ld %ld",
                       (long)ssheloop.select_timeout_ptr->tv_sec,
                       (long)ssheloop.select_timeout_ptr->tv_usec));

        /* Check if a signal was received after the last time they
           were checked.  If so, use a zero timeout instead of
           whatever we have scheduled now, so we don't end up waiting
           for the select() to return until the signal handler
           callback is called. */
        if (ssheloop.signal_fired)
            ssheloop.select_timeout_ptr = &ssheloop.select_timeout_no_wait;

        if (ssheloop.select_timeout_ptr != NULL || nfds > 0)
        {
            /* Raise the in_select flag. If signals arrive during the
               select() function call, the signal handler notices that and
               calls the callback for the signal immediately. */
#ifdef USE_POLL
            poll_timeout = -1;

            if (ssheloop.select_timeout_ptr != NULL)
            {
                long sec, usec;

                sec = ssheloop.select_timeout_ptr->tv_sec;
                usec = ssheloop.select_timeout_ptr->tv_usec;

                if (sec >= ((1 << 30) / THOUSAND))
                    poll_timeout = (int)(1 << 30);
                else
                    poll_timeout = (sec * THOUSAND) + (usec / THOUSAND );
            }


            SSH_DEBUG(SSH_D_LOWOK, ("Poll fds=%d timeout=%d.",
                                    nfds, poll_timeout));

            /* poll() is Very expensive, especially with large
               amounts of filedescriptors. So if we have a zero-timeout
               ready to go, then skip poll(). For fairness reasons
               we skip poll only a predefined amount of times before
               running a poll(). */
            if (done_something == true && poll_timeout == 0
                && poll_nopoll_counter < THOUSAND)
            {
                poll_nopoll_counter++;
                continue;
            }

            poll_nopoll_counter = 0;
            ssheloop.in_select = true;
            poll_return_value = poll(ssheloop.pfds, nfds, poll_timeout);
#else /* USE_POLL */
            SSH_DEBUG(SSH_D_LOWOK, ("Select."));

            ssheloop.in_select = true;
            poll_return_value = select(max_fd + 1, &readfds, &writefds, NULL,
                                       ssheloop.select_timeout_ptr);
#endif /* not USE_POLL */

            ssheloop.in_select = false;

            switch (poll_return_value)
            {
            case 0: /* Timeout */
                break;
            case -1: /* Error */
                switch (errno)
                {
                case ENOMEM:
                    SSH_DEBUG(
                            SSH_D_NICETOKNOW,
                            ("poll() exited due to insufficient resources."));
                    break;
                case EBADF: /* Bad file descriptor. */
                    ssh_fatal("Bad file descriptor in the event loop.");
                    break;
                case EINTR: /* Caught a signal. */
                    SSH_DEBUG(SSH_D_NICETOKNOW,
                              ("poll() exited because of a caught signal."));
                    break;
                case EINVAL: /* Invalid time limit. */
                    ssh_fatal("Bad time limit in the event loop.");
                    break;
                default:
#ifdef DEBUG_LIGHT
                    {
                        int errno_val = errno;
                        SSH_DEBUG(SSH_D_UNCOMMON,
                                  ("poll() returned %d", errno_val));
                    }
#endif /* DEBUG_LIGHT */
                    break;
                }
                break;

            default: /* Some IO is ready */
#ifdef USE_POLL
                for (idx = 0; idx < nfds && poll_return_value > 0; idx++)
                {
                    short revents;
                    int reqs;

                    revents = ssheloop.pfds[idx].revents;
                    if (revents == 0)
                        continue;

                    ssheloop.pfds[idx].revents = 0;
                    poll_return_value--;

                    /* If poll wakes up for multiple fd's the callback
                       for first may cancel the second, thus this may be
                       null. */
                    iorec_temp =
                        ssheloop.fd_to_record_map[ssheloop.pfds[idx].fd];
                    if (iorec_temp == NULL)
                        continue;

                    SSH_ASSERT(iorec_temp->fd == ssheloop.pfds[idx].fd);

                    if (iorec_temp->killed == true)
                        continue;

                    reqs = iorec_temp->request;
                    if ((reqs & SSH_IO_READ) != 0)
                    {
                        if (revents & (POLLERR|POLLHUP|POLLNVAL))
                        {
                            /* If an error occurs, call a callback
                               only once. */
                            SSH_DEBUG(99, ("pollnval fd=%d!", iorec_temp->fd));
                            (*iorec_temp->callback)(SSH_IO_READ,
                                                    iorec_temp->context);
                            continue;
                        }
                        else if (revents & (POLLIN|POLLPRI))
                        {
                            SSH_DEBUG(99, ("pollin fd=%d!", iorec_temp->fd));
                            (*iorec_temp->callback)(SSH_IO_READ,
                                                    iorec_temp->context);
                        }
                    }

                    /* Handle might have been killed on callback */
                    if (iorec_temp->killed == true)
                        continue;

                    reqs = iorec_temp->request;
                    if ((reqs & SSH_IO_WRITE) != 0)
                    {
                        if (revents & (POLLERR|POLLHUP|POLLNVAL))
                        {
                            /* If an error occurs, call a callback
                               only once. */
                            SSH_DEBUG(99, ("pollnvalfd=%d!", iorec_temp->fd));
                            (*iorec_temp->callback)(SSH_IO_WRITE,
                                                    iorec_temp->context);
                            continue;
                        }
                        else if (revents & POLLOUT)
                        {
                            SSH_DEBUG(99, ("pollout fd=%d", iorec_temp->fd));
                            (*iorec_temp->callback)(SSH_IO_WRITE,
                                                    iorec_temp->context);
                        }
                    }
                }
                SSH_ASSERT(poll_return_value == 0);
#else
                iorec_temp = ssheloop.io_records;
                while (iorec_temp != NULL)
                {
                    SshEloopIO *iorec_ptr;

                    if ((FD_ISSET(iorec_temp->fd, &readfds)) &&
                        (iorec_temp->killed == false) &&
                        (iorec_temp->request & SSH_IO_READ))
                        (*iorec_temp->callback)(
                                SSH_IO_READ,
                                iorec_temp->context);

                    if ((FD_ISSET(iorec_temp->fd, &writefds)) &&
                        (iorec_temp->killed == false) &&
                        (iorec_temp->request & SSH_IO_WRITE))
                        (*iorec_temp->callback)(SSH_IO_WRITE,
                                                iorec_temp->context);

                    iorec_ptr = &(iorec_temp->next);
                    iorec_temp = iorec_temp->next;
                }
#endif /* !USE_POLL */
                break;
            }
        }
    }
}
