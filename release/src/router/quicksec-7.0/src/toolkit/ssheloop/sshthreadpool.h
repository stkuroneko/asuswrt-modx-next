/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Thread pool API definition. Thread pool caches threads to avoid
   thread creation overhead, which on many platforms can be severe.
*/

#ifdef HAVE_THREADS

#include "sshthread.h"

#ifndef SSH_THREADPOOL_H
#define SSH_THREADPOOL_H

typedef struct SshThreadPoolRec *SshThreadPool;

typedef struct SshThreadPoolParamsRec {
  /* The minimum numbers of threads on the pool. This number of
     threads is created at the creation time of the pool. Setting this
     argument to nonzero is reasonalbe only in situations where
     performance is critical. */
  uint32_t min_threads;

  /* Maximum number of threads in the pool. If set to zero, there is
     no maximum number for threads in the pool (except the OS limit,
     which is dependent of the OS and thread library version) */
  uint32_t max_threads;
} *SshThreadPoolParams, SshThreadPoolParamsStruct;

/* Creates a thread pool. The params define how the pool behaves. If params is
   NULL, all the arguments get their default values. */
SshThreadPool ssh_thread_pool_create(SshThreadPoolParams params);

/* Waits for all of the threads in the pool to finish their execution
   and destroys the pool. No more thread starts will be accepted to
   the pool. It is fatal error to call this routine multiple times
   (from separate threads, for example.) */
void ssh_thread_pool_destroy(SshThreadPool pool);

/* Starts a execution of a thread from the pool. If the argument
   `queue' is false, and there a new thread is prohibited from
   starting (all allowed threads in use), then the `func' is not
   called and false is returned. If the pool is being destructed, then
   false is returned. Otherwise, either a thread starts executing at
   `func' immediately or at some later time (if `queue' is true and no
   threads are immediately available).

   Notice: The return value of 'func' is ignored, thus in effect the
   'func' has return value of void instead of void*, but the latter is
   still used to allow replacement of ssh_thread_create with
   ssh_thread_pool_start as painless as possible. */
bool ssh_thread_pool_start(SshThreadPool pool, bool queue,
                              SshThreadFuncCB func, void *context);

#endif /* SSH_THREADPOOL_H */
#endif /* HAVE_THREADS */
