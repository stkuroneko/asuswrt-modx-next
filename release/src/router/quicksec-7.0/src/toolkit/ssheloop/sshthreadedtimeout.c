/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshtimeouts.h"

#ifndef HAVE_THREADS

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

/* Initialize function for timeouts in multithreaded environment. If program
   uses multiple threads, it MUST call this function before calling
   ssh_register_threaded_timeout function. If the system environment does not
   support threads this will call ssh_fatal. If program does not use multiple
   threads it should not call this function, but it may still call
   ssh_register_threaded_timeout. This function MUST be called from the SSH
   main thread after the event loop has been initialized. */
void ssh_threaded_timeouts_init(void)
{
    ssh_fatal("No thread support in the system. "
              "Recompile with --with-threads=xxx to add one");
}

/* Uninitialize multithreading environment. This should be called before the
   program ends. After this is called the program MUST NOT call any other
   ssh_register_threaded_timeout functions before calling the
   ssh_threaded_timeouts_init function again. This function MUST be called from
   the SSH main thread. */
void ssh_threaded_timeouts_uninit(void)
{
    ssh_fatal("No thread support in the system. "
              "Recompile with --with-threads=xxx to add one");
}

bool
ssh_register_threaded_timeout(
        long seconds,
        long microseconds,
        SshTimeoutCallback callback,
        void *context)
{
    bool result = false;

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

    return result;
}

#endif /* HAVE_THREADS */
