/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Threaded message box interface implementation. This implementation
   is platform-independent, and relies on the sshmutex.h,
   and sshthreadpool.h abstractions.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshthreadedmbox.h"
#include "sshmutex.h"
#include "sshthread.h"
#ifdef DEBUG_LIGHT
#include "sshadt.h"
#include "sshadt_map.h"
#endif /* DEBUG_LIGHT */
#include "sshtimeouts.h"
#include "sshthreadpool.h"

#define SSH_DEBUG_MODULE "SshThreadedMbox"

/* We have two implementations: One using threads, and the other not,
   since the non-thread one is simpler and of course -- doesn't have
   threads. Doh. */

#ifdef HAVE_THREADS

struct SshThreadedMboxMsg
{
    SshThreadedMboxThreadCB thread_cb;
    void *ctx;
    struct SshThreadedMboxMsg *next;
};

struct SshThreadedMboxThreadState
{
    struct SshThreadedMboxRec *mbox;
    struct SshThreadedMboxMsg *msg;
};

struct SshThreadedMboxRec
{
    /* This mutex is used to lock all concurrent accesses to this
       structure. */
    SshMutex mutex;

    /* Maximum number of concurrent threads that are allowed to be
       executing on the thread side. */
    int32_t max_threads;

    /* Current number of threads executing */
    uint32_t num_threads;

    /* This is set to true if the mbox is being destroyed. Any callback
       returning must check this flag and then check if num_callbacks ==
       0, and perform final destruction if so. */
    bool destroyed;

    uint32_t num_callbacks;

    /* Queue of messages to threads */
    struct SshThreadedMboxMsg *thread_queue;

    /* Pointer to the last-elem-next thread_queue */
    struct SshThreadedMboxMsg **thread_queue_last_ptr;

    /* Freelist of SshThreadedMboxMsg objects */
    struct SshThreadedMboxMsg *message_freelist;

#ifdef DEBUG_LIGHT
    /* Map of all our threads that we have created */
    SshADTContainer thread_map;
#endif /* DEBUG_LIGHT */

    /* If max_threads is 0, then there is no threads, and we must handle
       the is_thread handling differently through data in the mbox
       structure instead. This is used only is max_threads == 0. */
    bool single_is_thread;

    /* Thread pool */
    SshThreadPool thread_pool;
};

#define SSH_MBOX_MESSAGE_FREELIST_INITIAL_SIZE 10

bool
mbox_message_freelist_alloc(
        SshThreadedMbox mbox)
{
    void *item;
    void *list = NULL;
    int i;

    for (i = 0; i < SSH_MBOX_MESSAGE_FREELIST_INITIAL_SIZE; i++)
    {
        item = ssh_calloc(1, sizeof(struct SshThreadedMboxMsg));

        if (item == NULL)
          goto fail;
        *((void **)item) = list;
        list = item;
    }
    mbox->message_freelist = list;
    return true;

   fail:
    while (list)
    {
        item = *((void **)list);
        ssh_free(list);
        list = item;
    }
    return false;
}

void
mbox_message_freelist_free(
        SshThreadedMbox mbox)
{
    void *list = mbox->message_freelist;
    void *next;

    SSH_DEBUG(SSH_D_HIGHOK, ("Freeing Mbox message structure freelist"));

    while (list)
    {
        next = *((void **)list);
        ssh_free(list);
        list = next;
    }
}


static struct SshThreadedMboxMsg *
ssh_threaded_mbox_message_alloc(
        SshThreadedMbox mbox)
{
    struct SshThreadedMboxMsg *item = mbox->message_freelist;

    if (item != NULL)
    {
        mbox->message_freelist = *((void **)(item));
    }
    else
    {
        item = ssh_malloc(sizeof(*item));
    }

    return item;
}


static void
ssh_threaded_mbox_freelist_put(
        SshThreadedMbox mbox,
        struct SshThreadedMboxMsg *item)
{
    *((void **)(item)) = mbox->message_freelist;
    mbox->message_freelist = item;
}


static void
ssh_threaded_mbox_destroy_final(
        SshThreadedMbox mbox);

/* Put a message to be sent to the eloop side */
bool
ssh_threaded_mbox_send_to_eloop(
        SshThreadedMbox mbox,
        SshThreadedMboxEloopCB eloop_cb,
        void *ctx)
{
    SSH_ASSERT(eloop_cb != NULL);

    SSH_DEBUG(12, ("to eloop: eloop_cb %p, ctx %p", eloop_cb, ctx));

    ssh_mutex_lock(mbox->mutex);

    if (mbox->destroyed)
    {
        ssh_mutex_unlock(mbox->mutex);
        SSH_DEBUG(SSH_D_FAIL,
                  ("Failed sending message to event loop, mbox destroyed: "
                   "eloop_cb %p, ctx %p", eloop_cb, ctx));
        return false;
    }

    ssh_mutex_unlock(mbox->mutex);

    /* If there is no threads used at *all*, then we *are* currently
       running in eloop and cannot postpone that actual call (or we'll
       create deadlock situations) */
    if (mbox->max_threads == 0)
    {
        bool was_thread = mbox->single_is_thread;

        ssh_mutex_lock(mbox->mutex);
        mbox->num_callbacks++;
        ssh_mutex_unlock(mbox->mutex);

        mbox->single_is_thread = false;

        (*eloop_cb)(ctx);
        mbox->single_is_thread = was_thread;

        ssh_mutex_lock(mbox->mutex);
        mbox->num_callbacks--;
        ssh_mutex_unlock(mbox->mutex);

        return true;
    }

    if (ssh_register_threaded_timeout(0, 0, eloop_cb, ctx) != true)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Failed creating threaded timeout to event loop: "
                   "eloop_cb %p, ctx %p", eloop_cb, ctx));
        return false;
    }

    return true;
}

/* Thread runner. This will start with the given message and emit
   it. After that, it will check the thread queue and process a
   message from there if any exist (ad infinitum). Finally it will
   check the destroyed flag and num_callbacks value and proceed with
   final destruction if necessary. */

static void *
ssh_threaded_mbox_thread_start(
        void *ctx)
{
    struct SshThreadedMboxThreadState *state = ctx;
    struct SshThreadedMboxMsg *msg = state->msg;
    SshThreadedMbox mbox = state->mbox;
    SshThread thread;
    SshThreadedMboxThreadCB callback_function;
    void *callback_context;
    bool more_work;

    SSH_DEBUG(13, ("thread starting with msg %p, ctx %p", msg, msg->ctx));

    thread = ssh_thread_current();

#ifdef DEBUG_LIGHT
    /* put us into the thread map, so we can later tell we're a true thread */
    ssh_mutex_lock(mbox->mutex);
    ssh_adt_put(mbox->thread_map, &thread);
    SSH_ASSERT(ssh_adt_get_handle_to_equal(mbox->thread_map, &thread)
               != SSH_ADT_INVALID);
    ssh_mutex_unlock(mbox->mutex);
#endif /* DEBUG_LIGHT */

    /* not needed anymore, remove the dangling pointer */
    state->msg = NULL;

    callback_function = msg->thread_cb;
    callback_context = msg->ctx;
    more_work = true;

    ssh_mutex_lock(mbox->mutex);
    ssh_threaded_mbox_freelist_put(mbox, msg);
    ssh_mutex_unlock(mbox->mutex);

    while (more_work)
    {
        more_work = false;

        callback_function(callback_context);

        ssh_mutex_lock(mbox->mutex);

        if (mbox->thread_queue != NULL)
        {
            msg = mbox->thread_queue;
            mbox->thread_queue = msg->next;
            msg->next = NULL;

            if (&msg->next == mbox->thread_queue_last_ptr)
            {
                mbox->thread_queue_last_ptr = &mbox->thread_queue;
            }

            callback_function = msg->thread_cb;
            callback_context = msg->ctx;

            ssh_threaded_mbox_freelist_put(mbox, msg);

            more_work = true;
        }

        ssh_mutex_unlock(mbox->mutex);

        SSH_DEBUG(
                13,
                ("thread has more work to do with func %p, ctx %p",
                 callback_function,
                 callback_context));
    }

    /* Done. Fall out, destruct self state. */

    ssh_mutex_lock(mbox->mutex);

    mbox->num_threads--;
    mbox->num_callbacks--;

#ifdef DEBUG_LIGHT
    ssh_adt_delete(mbox->thread_map,
                   ssh_adt_get_handle_to_equal(mbox->thread_map, &thread));
#endif /* DEBUG_LIGHT */

    SSH_DEBUG(13, ("thread done, %d threads left",
                   mbox->num_threads));

    ssh_mutex_unlock(mbox->mutex);

    ssh_free(state);

    return NULL;
}

/* Put a message to be sent to the thread side */
bool
ssh_threaded_mbox_send_to_thread(
        SshThreadedMbox mbox,
        SshThreadedMboxThreadCB thread_cb,
        void *ctx)
{
    struct SshThreadedMboxMsg *msg;
    struct SshThreadedMboxThreadState *state;

    SSH_ASSERT(thread_cb != NULL);

    SSH_DEBUG(12, ("to thread: thread_cb %p, ctx %p",
                   thread_cb, ctx));

    ssh_mutex_lock(mbox->mutex);

    if (mbox->destroyed)
    {
        ssh_mutex_unlock(mbox->mutex);
        SSH_DEBUG(SSH_D_FAIL,
                  ("Failed sending message to thread, mbox destroyed: "
                   "thread_cb %p, ctx %p", thread_cb, ctx));
        return false;
    }

    ssh_mutex_unlock(mbox->mutex);

    /* If max_threads == 0, we perform the call directly from here. */
    if (mbox->max_threads == 0)
    {
        bool was_thread = mbox->single_is_thread;

        ssh_mutex_lock(mbox->mutex);
        mbox->num_callbacks++;
        ssh_mutex_unlock(mbox->mutex);

        mbox->single_is_thread = true;

        SSH_DEBUG(12, ("single-threaded fall-through call"));
        (*thread_cb)(ctx);

        mbox->single_is_thread = was_thread;

        ssh_mutex_lock(mbox->mutex);
        mbox->num_callbacks--;
        ssh_mutex_unlock(mbox->mutex);

        return true;
    }

    ssh_mutex_lock(mbox->mutex);

    /* We need message struct, initialize */
    msg = ssh_threaded_mbox_message_alloc(mbox);
    if (msg == NULL)
    {
        ssh_mutex_unlock(mbox->mutex);
        SSH_DEBUG(SSH_D_FAIL,
                  ("Memory allocation failed: "
                   "thread_cb %p, ctx %p", thread_cb, ctx));
        return false;
    }
    msg->thread_cb = thread_cb;
    msg->ctx = ctx;
    msg->next = NULL;

    /* If max_threads == -1 or num_threads < max_threads, spawn a new thread */
    if (mbox->max_threads == -1 || mbox->num_threads < mbox->max_threads)
    {
        mbox->num_threads++;
        mbox->num_callbacks++;

        SSH_DEBUG(12, ("creating new thread, %d threads total",
                       mbox->num_threads));

        state = ssh_malloc(sizeof(*state));
        if (!state)
        {
            ssh_threaded_mbox_freelist_put(mbox, msg);
            mbox->num_threads--;
            mbox->num_callbacks--;
            ssh_mutex_unlock(mbox->mutex);

            SSH_DEBUG(SSH_D_FAIL,
                      ("Memory allocation failed: "
                       "thread_cb %p, ctx %p", thread_cb, ctx));

            return false;
        }

        state->mbox = mbox;
        state->msg = msg;

        ssh_mutex_unlock(mbox->mutex);

        /* Umm, actually, this should never happen.. */
        if (!ssh_thread_pool_start(mbox->thread_pool, true,
                                   ssh_threaded_mbox_thread_start, state))
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Failed to start thread pool: "
                       "thread_cb %p, ctx %p", thread_cb, ctx));
            return false;
        }

        return true;
    }

    /* Otherwise, queue the message. A thread done its work will always
       check the thread side queue, and process messages in there before
       exiting. */

    SSH_DEBUG(12, ("queueing msg %p, %d thread limit reached",
                   msg, mbox->max_threads));

    *mbox->thread_queue_last_ptr = msg;
    mbox->thread_queue_last_ptr = &msg->next;
    ssh_mutex_unlock(mbox->mutex);

    return true;
}

#ifdef DEBUG_LIGHT
/* Returns true if the current executing thread is running in the
   "thread" context side of the mbox messages */
bool
ssh_threaded_mbox_is_thread(
        SshThreadedMbox mbox)
{
    bool is_thread;
    SshThread thread;

    if (mbox->max_threads == 0)
      return mbox->single_is_thread;

    thread = ssh_thread_current();

    ssh_mutex_lock(mbox->mutex);
    is_thread = ssh_adt_get_handle_to_equal(mbox->thread_map, &thread)
      != SSH_ADT_INVALID;
    ssh_mutex_unlock(mbox->mutex);

    return is_thread;
}

static unsigned long
void_hash(
        const void *ptr,
        void *ctx)
{
    return (unsigned long) *(void**)ptr;
}

static int
void_cmp(
        const void *ptr1,
        const void *ptr2,
        void *ctx)
{
    if (*(void **) ptr1 == *(void **) ptr2)
    {
        return 0;
    }

    if (*(void **) ptr1 < *(void **) ptr2)
    {
        return -1;
    }

    return 1;
}
#endif /* DEBUG_LIGHT */

/* Create a new mbox */
SshThreadedMbox ssh_threaded_mbox_create(int32_t max_threads)
{
    SshThreadedMbox mbox;

    mbox = ssh_calloc(1, sizeof(*mbox));

    if (!mbox)
      return NULL;

    if (!mbox_message_freelist_alloc(mbox))
    {
        ssh_free(mbox);
        return NULL;
    }

    mbox->max_threads = max_threads;
    mbox->thread_queue_last_ptr = &mbox->thread_queue;

    /* Initialize mutex and condvars */
    mbox->mutex = ssh_mutex_create("thread_mbox", 0);

    if (!mbox->mutex)
    {
        ssh_threaded_mbox_destroy_final(mbox);
        return NULL;
    }

#ifdef DEBUG_LIGHT
    mbox->thread_map = ssh_adt_create_generic(SSH_ADT_MAP,
                                              SSH_ADT_HASH, void_hash,
                                              SSH_ADT_COMPARE, void_cmp,
                                              SSH_ADT_SIZE, sizeof(SshThread),
                                              SSH_ADT_ARGS_END);

    if (!mbox->thread_map)
    {
        ssh_threaded_mbox_destroy_final(mbox);
        return NULL;
    }
#endif /* DEBUG_LIGHT */

    if (max_threads > 0)
    {
        SshThreadPoolParamsStruct params;
        params.min_threads = 0;
        params.max_threads = max_threads;
        mbox->thread_pool = ssh_thread_pool_create(&params);

        if (!mbox->thread_pool)
        {
            ssh_threaded_mbox_destroy_final(mbox);
            return NULL;
        }
    }
    else
      mbox->thread_pool = NULL;

    mbox->destroyed = false;
    return mbox;
}

/* This must be called from eloop context */
void
ssh_threaded_mbox_destroy(
        SshThreadedMbox mbox)
{
    SSH_DEBUG(12, ("destroying mbox %p", mbox));

    SSH_ASSERT(mbox->destroyed == false);

    if (mbox->thread_pool != NULL)
    {
        ssh_thread_pool_destroy(mbox->thread_pool);
    }

    /* From this point onwards, there is no other threads concurrently
       accessing the `mbox' state. */
    ssh_threaded_mbox_destroy_final(mbox);
}


/* This routine is called from the eloop single-threaded context. */
static void
ssh_threaded_mbox_destroy_final(
        SshThreadedMbox mbox)
{
    SSH_ASSERT(mbox->num_callbacks == 0);
    SSH_ASSERT(mbox->num_threads == 0);
    SSH_ASSERT(mbox->thread_queue == NULL);

#ifdef DEBUG_LIGHT
    if (mbox->thread_map != NULL)
    {
        ssh_adt_destroy(mbox->thread_map);
    }
#endif /* DEBUG_LIGHT */

    if (mbox->mutex)
    {
        ssh_mutex_destroy(mbox->mutex);
    }

    mbox_message_freelist_free(mbox);

    ssh_free(mbox);
}

#else /* !HAVE_THREADS */

struct SshThreadedMboxRec
{
    /* true if we're being destructed. In that case, final destruction
       will happen when num_callbacks reaches 0 */
    bool destroyed;

    /* Calculate levels of callbacks we're handling */
    uint32_t num_callbacks;

    /* Whether we're in the thread side (true) or eloop side (false) */
    bool in_thread;
};

SshThreadedMbox
ssh_threaded_mbox_create(
        int32_t max_threads)
{
    SshThreadedMbox mbox;
    mbox = ssh_calloc(1, sizeof(*mbox));
    return mbox;
}

void
ssh_threaded_mbox_destroy(
        SshThreadedMbox mbox)
{
    SSH_ASSERT(!mbox->destroyed);
    mbox->destroyed = true;
    if (mbox->num_callbacks == 0)
      ssh_free(mbox);
}

bool
ssh_threaded_mbox_send_to_eloop(
        SshThreadedMbox mbox,
        SshThreadedMboxEloopCB eloop_cb,
        void *ctx)
{
    bool was_thread;

    SSH_ASSERT(eloop_cb != NULL);

    if (mbox->destroyed)
      return false;

    was_thread = mbox->in_thread;
    mbox->in_thread = false;

    mbox->num_callbacks++;
    (*eloop_cb)(ctx);
    mbox->num_callbacks--;
    mbox->in_thread = was_thread;

    if (mbox->destroyed && mbox->num_callbacks == 0)
      ssh_free(mbox);

    return true;
}

bool
ssh_threaded_mbox_send_to_thread(
        SshThreadedMbox mbox,
        SshThreadedMboxThreadCB thread_cb,
        void *ctx)
{
    bool was_thread;

    SSH_ASSERT(thread_cb != NULL);

    if (mbox->destroyed)
      return false;

    was_thread = mbox->in_thread;
    mbox->in_thread = true;

    mbox->num_callbacks++;
    (*thread_cb)(ctx);
    mbox->num_callbacks--;
    mbox->in_thread = was_thread;

    if (mbox->destroyed && mbox->num_callbacks == 0)
      ssh_free(mbox);

    return true;
}

#ifdef DEBUG_LIGHT
bool
ssh_threaded_mbox_is_thread(
        SshThreadedMbox mbox)
{
    return mbox->in_thread;
}
#endif /* DEBUG_LIGHT */

#endif /* HAVE_THREADS */
