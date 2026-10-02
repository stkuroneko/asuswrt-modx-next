/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Multithread timeouts support
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshmutex.h"

#define SSH_DEBUG_MODULE "SshMtTimeouts"

struct SshTimeoutMessage
{
    long seconds;
    long microseconds;
    SshTimeoutCallback callback;
    void *context;

    struct SshTimeoutMessage *next;
};

/* SSH library functions can only be called from single thread. This SSH main
   thread is the thread that is running the event loop. If the program is
   multiple threads and the other threads want to call some SSH library
   functions they must pass the execution of that code to the SSH main thread.
   Only method of doing that is to call ssh_register_threaded_timeout. That
   function can be called from other threads also, and it will pass the timeout
   given to it to the SSH main thread. When the timeout expires it is run on
   the SSH main thread. If you want to the call to be done as soon as possible
   use zero length timeout. The SSH library contains few other functions that
   can be called from other threads also. Each of those functions contains a
   note saying that they can be called from other threads also. */

/* Threaded environment context */
struct SshThreadTimeoutContext
{
    SshMutex mutex;
    SshIOHandle pipe_read_fd;
    SshIOHandle pipe_write_fd;

    struct SshTimeoutMessage *items;
};

/* Global multi thread context structure. If this is NULL then
   ssh_threaded_timeout_init is not called, and we are not using threads */
struct SshThreadTimeoutContext *ssh_threaded_timeout_context = NULL;


static void
ssh_threaded_timeout_register_to_event_loop(
        struct SshThreadTimeoutContext *ctx)
{
    struct SshTimeoutMessage *item;

    ssh_mutex_lock(ctx->mutex);

    item = ctx->items;
    while (item != NULL)
    {
        struct SshTimeoutMessage *next = item->next;

        ssh_register_timeout(
                NULL,
                item->seconds,
                item->microseconds,
                item->callback,
                item->context);

        ssh_free(item);

        item = next;
    }

    ctx->items = NULL;

    ssh_mutex_unlock(ctx->mutex);
}

/* This is the callback function that is called when the pipe_read_fd wakes up
   because there is data in the pipe. This function will first read everything
   from the pipe, and then take a mutex and insert all items in the timeout
   list ot the event loop timeout list. */
void
ssh_threaded_timeout_io_read(
        unsigned int events,
        void *context)
{
    struct SshThreadTimeoutContext *ctx = context;
    unsigned char buffer[16];

    if (events & SSH_IO_WRITE)
      ssh_fatal(
              "IO notification for write received, even when none requested");

    while (read(ctx->pipe_read_fd, buffer, sizeof(buffer)) > 0)
      ;

    ssh_threaded_timeout_register_to_event_loop(ctx);
}


/* Initialize function for timeouts in multithreaded environment. If program
   uses multiple threads, it MUST call this function before calling
   ssh_register_threaded_timeout function. If the system environment does not
   support threads this will call ssh_fatal. If program does not use multiple
   threads it should not call this function, but it may still call
   ssh_register_threaded_timeout. This function MUST be called from the SSH
   main thread after the event loop has been initialized. */
void
ssh_threaded_timeouts_init(
        void)
{
    int filedes[2];

    if (ssh_threaded_timeout_context)
    {
        ssh_fatal("Ssh_threaded_timeout_init called twice");
    }

    ssh_threaded_timeout_context =
        ssh_xcalloc(
                1,
                sizeof(*ssh_threaded_timeout_context));

    ssh_threaded_timeout_context->mutex =
        ssh_mutex_create(
                "ThreadedTimeoutItemLock",
                0);

    if (ssh_threaded_timeout_context->mutex == NULL)
    {
        ssh_fatal("Creating mutex failed in ssh_threaded_timeout_init");
    }

    if (pipe(filedes) != 0)
    {
        ssh_fatal(
                "Creating pipe failed in ssh_threaded_timeout_init : %s",
                strerror(errno));
    }

    /* Store the file descriptors to the structure */
    ssh_threaded_timeout_context->pipe_read_fd = filedes[0];
    ssh_threaded_timeout_context->pipe_write_fd = filedes[1];

    /* Install the read end to the event loop. */
    ssh_io_xregister_fd(
            ssh_threaded_timeout_context->pipe_read_fd,
            ssh_threaded_timeout_io_read,
            ssh_threaded_timeout_context);

    ssh_io_set_fd_request(
            ssh_threaded_timeout_context->pipe_read_fd,
            SSH_IO_READ);
}

/* Uninitialize multithreading environment. This should be called before the
   program ends. After this is called the program MUST NOT call any other
   ssh_register_threaded_timeout functions before calling the
   ssh_threaded_timeouts_init function again. This function MUST be called from
   the SSH main thread. */
void
ssh_threaded_timeouts_uninit(
        void)
{
    if (ssh_threaded_timeout_context == NULL)
    {
        ssh_fatal(
                "Ssh_threaded_timeout_uninit called before "
                "ssh_threaded_timeout_init was called");
    }

    ssh_threaded_timeout_register_to_event_loop(ssh_threaded_timeout_context);

    ssh_mutex_destroy(ssh_threaded_timeout_context->mutex);
    ssh_io_unregister_fd(ssh_threaded_timeout_context->pipe_read_fd, false);
    close(ssh_threaded_timeout_context->pipe_read_fd);
    close(ssh_threaded_timeout_context->pipe_write_fd);

    ssh_free(ssh_threaded_timeout_context);
    ssh_threaded_timeout_context = NULL;
}

bool
ssh_register_threaded_timeout(
        long seconds,
        long microseconds,
        SshTimeoutCallback callback,
        void *context)
{
    bool result = false;

    if (ssh_threaded_timeout_context == NULL)
    {
        if (ssh_register_timeout(
                    NULL,
                    seconds,
                    microseconds,
                    callback,
                    context)
            != NULL)
        {
            result = true;
        }
    }
    else
    {
        struct SshTimeoutMessage *item;

        item = ssh_calloc(1, sizeof *item);
        if (item != NULL)
        {
            item->seconds = seconds;
            item->microseconds = microseconds;
            item->callback = callback;
            item->context = context;

            ssh_mutex_lock(ssh_threaded_timeout_context->mutex);

            item->next = ssh_threaded_timeout_context->items;
            ssh_threaded_timeout_context->items = item;

            ssh_mutex_unlock(ssh_threaded_timeout_context->mutex);

            /* Wake up the ssh main thread in the event loop. We don't
               need to care if the pipe is full or something, we just do
               write and the event loop will wake up later. */
            write(ssh_threaded_timeout_context->pipe_write_fd, " ", 1);

            result = true;
        }
    }

    return result;
}
