/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Event loop for Win32.  This file implements timeouts and socket
   callbacks for Windows.
*/

#ifdef _WIN32_WCE

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshtimeoutsi.h"
#include "sshadt.h"
#include "sshadt_list.h"
#include "sshmutex.h"
#include "sshthreadpool.h"

#ifndef _WIN32_WCE
#include <process.h>
#include <sys/timeb.h>
#include <signal.h>
#endif /* _WIN32_WCE */

#define SSH_DEBUG_MODULE "SshEventLoop"

#define SSH_ELOOP_MAX_WINDOW_NAME_SIZE 255
#define SSH_ELOOP_WINDOW_NAME_PREFIX  TEXT("SSH_ELOOP_WINDOW")
#define SSH_ELOOP_TIMEOUT_FREELIST_INITIAL_SIZE 100
static TCHAR lpszSshWindowClassName[SSH_ELOOP_MAX_WINDOW_NAME_SIZE];

#ifdef UNICODE
#define ssh_eloop_strcat    wcscat
#define ssh_eloop_snprintf  _snwprintf
#else
#define ssh_eloop_strcat    strcat
#define ssh_eloop_snprintf  ssh_snprintf
#endif /* UNICODE */

typedef struct SshEventRec {
  void* link;
  HANDLE hevent;
  SshEventCallback callback;
  void* context;
  int unregistered;
} *SshEvent;

typedef struct SshSocketRec {
  struct SshSocketRec *next;
  SshIOHandle sock;
  SshIoCallback callback;
  void *context;
  Boolean cancelled;
#ifdef _WIN32_WCE
  HANDLE hevent;
#endif /* _WIN32_WCE */
} *SshSocket;

typedef struct SshSignalRec {
  int signal;
  SshSignalCallback callback;
  void *context;
  Boolean unregistered;
} *SshSignal;

typedef void (*SshEventLoopCallback)(void* context);
typedef struct SshIoCallbackParamsRec {
  SshIoCallback callback;
  unsigned int events;
  void* context;
} *SshIoCallbackParams;

/* This is used to queue messages that are received while executing a
   callback. Queued events are executed after the callback being
   executed returns. See ssh_eloop_process_queued_messages(). */
typedef struct SshQueuedMsgRec {
  WPARAM wparam;
  LPARAM lparam;
  HWND hWnd;
  UINT msg;
} *SshQueuedMsg;

/* Local prototypes */
#ifdef _WIN32_WCE
static unsigned _stdcall
#else
static void
#endif /* _WIN32_WCE */
the_event_loop(void* params);

static void ssh_event_loop_lock_timeouts(void);

static void ssh_event_loop_unlock_timeouts(void);


static void ssh_eloop_execute_event_callback(
  DWORD thread,
  SshEvent event);

/* Executes the timeout callback in the proper thread. When using
   ssh_event_loop_run(), timeouts are executed in the same thread
   than the event loop runs, but when using ssh_event_loop_start(),
   a special ssh_eloop_timeout_message is sent to the application
   thread, which calls the timeout callback. */
static void ssh_eloop_execute_timeout_callback(
  DWORD thread,
  SshTimeout timeout);


static LRESULT CALLBACK ssh_eloop_window_proc(HWND hWnd, UINT message,
                                              WPARAM wParam, LPARAM lParam);
static int ssh_event_loop_do_timeouts(void);
static int ssh_event_loop_compare_time(struct timeval *first,
                                       struct timeval *second);
static void ssh_eloop_get_current_time(struct timeval *tv);
static void
ssh_eloop_convert_relative_to_absolute(long seconds,
                                       long microseconds,
                                       struct timeval *timeval);

static void ssh_eloop_signal_handler(void *context);

#ifdef _WIN32_WCE
static void ssh_io_fd_complete(void *context);
#endif /* _WIN32_WCE */

/* Local variables */

static SshADTContainer ssh_eloop_events;

static SshADTContainer ssh_eloop_signals;

/* Window handle for the hidden window.  This window is used for receiving
   socket messages */
HWND ssh_eloop_hidden_window = NULL;

typedef struct SshEloopRec
{
  SshTimeoutContainerStruct to;
  /* Freelist of timeouts */
  SshTimeout timeout_freelist;
} *SshEloop, SshEloopStruct;

SshEloopStruct ssheloop;

/* The list of messages that are queued while the event loop
   is executing a callback. */
static SshADTContainer ssh_eloop_queued_msgs;

/* List of sockets for which we are listening for events. */
static SshSocket ssh_eloop_sockets = NULL;

/* Flag indicating whether we are currently processing a callback. */
static Boolean ssh_eloop_in_callback = FALSE;

/* Number of wait handles registered after starting the event loop. */
static int ssh_eloop_runtime_wait_handles;

/* Flag indicating we are running the event loop. */
static Boolean ssh_event_loop_running;

/* A mutex that is held whenever the system is executing a callback.  This
   lock is also used to protect event data structures; independent threads
   can call event loop functions only when they hold this lock.  This lock
   is manipulated using the ssh_event_loop_lock() and ssh_event_loop_unlock()
   functions. */

static CRITICAL_SECTION ssh_eloop_lock;

static CRITICAL_SECTION ssh_eloop_timeout_lock;

/* Thread ID of the thread holding ssh_eloop_lock mutex. Used for asserts. */
static unsigned ssh_eloop_lock_owner = 0;

/* Dynamically allocated msg identifier for socket messages */
static unsigned ssh_eloop_socket_msg = 0;

/* Dynamically allocated msg identifier for event messages */
static unsigned ssh_eloop_event_msg = 0;

/* Dynamically allocated msg identifier for timeout callback messages */
static unsigned ssh_eloop_timeout_msg = 0;

/* Dynamically allocated msg identifier for signal emulation messages */
static unsigned ssh_eloop_signal_msg = 0;

/* handle to wake up all threads after one thread has returned */
HANDLE thread_wake_handle;

/* The dummy event and the dummy event callbacks are used to ensure that we
   always have at least one event pending. Dummy event are set every time we
   register a timeout to wake up the event loop thread. */
static HANDLE ssh_dummy_event;
static void ssh_event_loop_dummy_event_callback(void *context)
{
  return;
}


/* */
static DWORD app_thread = 0;
static HANDLE eloop_thread = INVALID_HANDLE_VALUE;
/* ID of the thread running the event loop */
static DWORD eloop_thread_id = 0;


/* Data for waiting events in multiple threads. If the number of
   waitable events is more than 63 (MAXIMUM_WAIT_OBJECTS-1),
   waiting has to be performed in multiple threads with each
   thread capable of waiting up to 63 event handles. (Actually
   its 62 events plus a wakeup event.) The limitation of 63 events
   is built-in to MsgWaitForMultipleObjects(). */

#define SSH_MAXIMUM_REAL_WAIT_OBJECTS    (MAXIMUM_WAIT_OBJECTS - 2)

/* wait results returned by the event waiting function */
#define SSH_WAIT_TIMEOUT            1
#define SSH_WAIT_IO_COMPLETION      2
#define SSH_WAIT_WINDOWS_MSG        3
#define SSH_WAIT_ABANDONED          4
#define SSH_WAIT_HANDLE             5
#define SSH_WAIT_UNKNOWN            6

/* Context for a waiting thread. */
typedef struct SshWaitContextRec
{
  DWORD handle_count; /* number of handles in the array below */
  DWORD wait_timeout; /* timeout for the wait */

  HANDLE handles[MAXIMUM_WAIT_OBJECTS]; /* up to 63 handles */
  BOOL   take_all_input; /* Do we wait for QS_ALLINPUT or not.
                            Only one thread needs to do it */
  BOOL   free_context;
} *SshWaitContext, SshWaitContextStruct;

/* pool of threads */
static SshThreadPool ssh_eloop_thread_pool;

/* mutex guarding data from a child thread, and data protected
   by the mutex */
static SshMutex thread_data_lock;
/* determines whether the first thread has already returned */
static BOOL     thread_signaled;
/* variables for return data of the first thread */
DWORD  thread_return_value;
HANDLE thread_event_handle;
/* list of thread return values and handles */
typedef struct SshWaitResultRec
{
  DWORD  result;
  HANDLE event_handle;
} *SshWaitResult;
static SshADTContainer ssh_eloop_wait_return_values;

void ssh_timeout_freelist_alloc(SshEloop eloop)
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

void ssh_timeout_freelist_free(SshEloop eloop)
{
  void *next, *list;

  list = eloop->timeout_freelist;

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

/*****************************************************************************
 * The event loop - initialization, uninitialization, looping, window proc
 ****************************************************************************/

/* Initializes the event loop.  This must be called before any other
   event loop, timeout, or stream function.  The normal place for
   calling this is the applications WinMain function or the
   CWinApp::InitInstance function in MFC applications. */


void ssh_event_loop_initialize(void)
{
  WSADATA data;
  WORD version;
  int major_version, minor_version;
  int window_name_id = 0;
  WNDCLASS wc;

  ssh_event_loop_running = FALSE;

  /* If we already have the hidden window, then we have already been
     initialized. */
  if (ssh_eloop_hidden_window)
    {
      ssh_warning("ssh_event_loop_initialize called multiple times.");
      return;
    }

  /* Initialize event loop lock. */
  InitializeCriticalSection(&ssh_eloop_lock);

  InitializeCriticalSection(&ssh_eloop_timeout_lock);

  /* Clear the data structures. */
  ssh_eloop_sockets = NULL;


  /* Initialize list for event handles */
  ssh_eloop_events =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_SIZE, sizeof(struct SshEventRec),
                           SSH_ADT_ARGS_END
  );

  /* Initialize the list of queued messages. */
  ssh_eloop_queued_msgs =
    ssh_adt_create_generic(SSH_ADT_LIST, SSH_ADT_ARGS_END);

  /* Initialize the list of signals. */
  ssh_eloop_signals =
    ssh_adt_create_generic(SSH_ADT_LIST, SSH_ADT_ARGS_END);

  /* Initialize the Winsock library, requesting winsock version 1.1 */
  version = 0x0101;
  if (WSAStartup(version, &data) != 0)
    ssh_fatal("Initialization of Windows Sockets (WINSOCK) failed.");

  /* Check the winsock version. */
  major_version = HIBYTE(data.wVersion);
  minor_version = LOBYTE(data.wVersion);
  if (major_version < 1 || (major_version == 1 && minor_version < 1))
    ssh_fatal("Unsupported Winsock version %d.%d.  At least 1.1 required.",
              major_version, minor_version);

  /* Register per-application window messages */
  ssh_eloop_socket_msg = RegisterWindowMessage(TEXT("SSH SOCKET MESSAGE"));
  ssh_eloop_event_msg = RegisterWindowMessage(TEXT("SSH EVENT MESSAGE"));
  ssh_eloop_timeout_msg = RegisterWindowMessage(TEXT("SSH TIMEOUT MESSAGE"));
  ssh_eloop_signal_msg = RegisterWindowMessage(TEXT("SSH SIGNAL MESSAGE"));
  if (!ssh_eloop_socket_msg ||
      !ssh_eloop_event_msg ||
      !ssh_eloop_signal_msg ||
      !ssh_eloop_timeout_msg)
    ssh_fatal("ssh_event_loop_initialize: "
              "Cannot register custom window messages");

  ssh_dummy_event = CreateEvent(NULL, FALSE, FALSE, NULL);

  ssh_event_loop_register_handle(ssh_dummy_event, FALSE, NULL, NULL);

  /* Event loop remains locked until uninitialized */
  /*  ssh_event_loop_lock(); */

  /* Create a hidden window for posting timer and socket messages. */
  /* If we fail to create a window with our name, we will add
     this number to our prefix and keep trying until we succeed. */

  /* Register a window class with our own window procedure. */
  memset(&wc, 0, sizeof(wc));
  wc.lpfnWndProc = ssh_eloop_window_proc;
  memset(lpszSshWindowClassName, 0, sizeof(lpszSshWindowClassName));
  ssh_eloop_strcat(lpszSshWindowClassName, SSH_ELOOP_WINDOW_NAME_PREFIX);
  wc.lpszClassName = lpszSshWindowClassName;

  /* register a new windows class. limit iterations to 1000 times until
     a class can be registered */
  while (RegisterClass(&wc) == 0 && window_name_id < 1000)
    {
      if (GetLastError() == ERROR_CLASS_ALREADY_EXISTS || GetLastError() == 0)
        {
          SSH_DEBUG(SSH_D_UNCOMMON, ("Register class failed. "
                                     "Trying with alternative names"));
          ssh_eloop_snprintf(lpszSshWindowClassName,
                             sizeof(lpszSshWindowClassName),
                             TEXT("%s-%d"), SSH_ELOOP_WINDOW_NAME_PREFIX,
                             window_name_id++);
          continue;
        }
      ssh_fatal("Could not create a window clas for eloop. "
                "GetLastError is %d.", GetLastError());
    }

  /* Create socket window */
  ssh_eloop_hidden_window = CreateWindow(wc.lpszClassName, TEXT(""), 0, 0,
                                         0, 0, 0, NULL, NULL, NULL, NULL);

  ssh_timeout_container_initialize(&ssheloop.to);
  /* Alloc the freelist of timeouts */
  ssh_timeout_freelist_alloc(&ssheloop);

  if (ssh_eloop_hidden_window == NULL)
    ssh_fatal("ssh_event_loop_initialize: cannot create window.");

  /* book keeping data for a pool of event waiting threads */
  if ((ssh_eloop_thread_pool = ssh_thread_pool_create(NULL)) == NULL)
    ssh_fatal("ssh_event_loop_initialize: Cannot create thread pool");

  thread_data_lock = ssh_mutex_create(NULL, 0);
  SSH_ASSERT(thread_data_lock != NULL);

  thread_wake_handle = CreateEvent(NULL, TRUE, FALSE, NULL);
  SSH_ASSERT((DWORD)thread_wake_handle != ERROR_INVALID_HANDLE);

  ssh_eloop_wait_return_values = ssh_adt_create_generic(SSH_ADT_LIST,
                                                        SSH_ADT_ARGS_END);
}


/* Uninitializes the event loop, and frees resources used by it.  This
   automatically cancels any pending timeouts and unregisters file
   descriptors.  This must not be called from within an event loop
   callback, unless the application exits without the callback ever
   returning.  A typical place for calling this function would be in
   the WinMain function, or in CWinApp::ExitInstance in MFC based
   applications. */

void ssh_event_loop_uninitialize(void)
{
  SshSignal ssh_signal;
  SshADTHandle handle;
  SshSocket socket, next_socket;

  /* Destroy the hidden window. */
  if (ssh_eloop_hidden_window == NULL)
    {
      ssh_warning("ssh_event_loop_uninitialize: not initialized");
      return;
    }
  DestroyWindow(ssh_eloop_hidden_window);
  ssh_eloop_hidden_window = NULL;

  UnregisterClass(lpszSshWindowClassName, GetModuleHandle(NULL));

  /* Free pending timeouts. */
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, SSH_ALL_CONTEXTS);
  ssh_timeout_container_uninitialize(&ssheloop.to);

  /* Free the timeout free list */
  ssh_timeout_freelist_free(&ssheloop);

  /* Free socket records. */
  for (socket = ssh_eloop_sockets; socket; socket = next_socket)
    {
      next_socket = socket->next;
      closesocket(socket->sock);
      ssh_xfree(socket);
    }
  ssh_eloop_sockets = NULL;

  ssh_event_loop_unregister_handle(ssh_dummy_event);

  /* Delete the event and timeout lists */
  ssh_adt_destroy(ssh_eloop_events);

  ssh_adt_destroy(ssh_eloop_queued_msgs);

  handle = ssh_adt_enumerate_start(ssh_eloop_signals);
  while (handle != SSH_ADT_INVALID)
    {
      ssh_signal = ssh_adt_get(ssh_eloop_signals, handle);
      handle = ssh_adt_enumerate_next(ssh_eloop_signals, handle);

      ssh_unregister_signal(ssh_signal->signal);
    }
  ssh_adt_destroy(ssh_eloop_signals);

  CloseHandle(ssh_dummy_event);

  /* free objects for thread waiting */
  ssh_thread_pool_destroy(ssh_eloop_thread_pool);
  ssh_mutex_destroy(thread_data_lock);
  CloseHandle(thread_wake_handle);
  ssh_adt_destroy(ssh_eloop_wait_return_values);

  /* Clean up the windows sockets library. */
  WSACleanup();

  /* ssh_event_loop_unlock(); */

  /* Destroy event loop lock object. */
  DeleteCriticalSection(&ssh_eloop_lock);
  DeleteCriticalSection(&ssh_eloop_timeout_lock);
}


/*
  ssh_event_loop_run(): Traditional interface for entering event-loop

  This runs the original SSH event loop within the calling thread.
  This function returns when the event loop exits via the ssh_event_loop_abort
  or defined exit criteria (No pending timeouts, no registered filehandles).
*/
void ssh_event_loop_run(void)
{
  eloop_thread = GetCurrentThread();

  /* stay in the loop until process ends */
  the_event_loop((void*)GetCurrentThreadId());
}

/*
   ssh_event_loop_start(): Starts "background" event loop processing

   This runs the SSH event loop implementation in a separate thread,
   returning almost immediately to the caller. Event loop can be
   stopped using ssh_event_loop_abort(). The SSH eloop callbacks are
   processed, when the application runs the dispatch message.
*/
void ssh_event_loop_start(void)
{
#if _WIN32_WCE
  eloop_thread = CreateThread(NULL, 0, the_event_loop,
                              (void *)GetCurrentThreadId(),
                              0, NULL);
#else
  eloop_thread = (HANDLE)_beginthread(the_event_loop,
                                      0,
                                      (void *)GetCurrentThreadId());
#endif /* _WIN32_WCE */

  /* stay in the loop until process ends */
  if (eloop_thread == (HANDLE)-1)
    ssh_fatal("ssh_event_loop_start(): _beginthread() failed!");
}


void ssh_event_loop_abort(void)
{
  PostThreadMessage(eloop_thread_id, WM_QUIT, 0,0);

  if (eloop_thread_id != GetCurrentThreadId() && ssh_event_loop_running)
    {
      /* Wait for the event loop thread to stop.  Note that the thread may
         already be finished when we call WaitForSingleObject().  In this
         case the eloop_thread handle is invalid, and the function ignores
         it and just returns an error. */

      /* Wake up the event loop thread. */
      SetEvent(ssh_dummy_event);

      WaitForSingleObject(eloop_thread, INFINITE);
    }
}


static Boolean ssh_eloop_has_unregistered_handles()
{
  SshADTHandle handle;
  handle = ssh_adt_enumerate_start(ssh_eloop_events);
  while (handle != SSH_ADT_INVALID)
    {
      SshEvent event;
      event = ssh_adt_get(ssh_eloop_events, handle);
       if (event->unregistered)
        return TRUE;
      handle = ssh_adt_enumerate_next(ssh_eloop_events, handle);
    }
   return FALSE;
}


/* === WAITING FOR EVENTS WITH THREADS === */

/* One thread waits for up to 62 (plus a wakeup) events here.
   The MsgWaitForMultipleObjects can only take 63 events at a
   time, so if we have more handles, we have to wait them in
   separate threads. */
void *ssh_event_thread_wait_for_events(void *context)
{
  /* extract data given to us */
  SshWaitContext ctx = (SshWaitContext)context;
  DWORD num_wait_handles = ctx->handle_count;
  HANDLE *wait_handles = ctx->handles;
  DWORD result;
  int   signaled_handle_index;

  /* add our wake event to the array */
  wait_handles[num_wait_handles] = thread_wake_handle;
  num_wait_handles++;

  /* wait for events */
  result = MsgWaitForMultipleObjects(
              num_wait_handles,
              wait_handles,
              FALSE,
              ctx->wait_timeout,
              ctx->take_all_input ? QS_ALLINPUT : 0);
  if (result == WAIT_FAILED)
    {
      /* Wait failed. This happens in rare occasions, for example when
         there is a closed handle registered into event loop. */
      DWORD error = GetLastError();

      if ((error != ERROR_INVALID_HANDLE) ||
          (ssh_eloop_has_unregistered_handles() == FALSE))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Wait Failed for unknown reason, "
                                  "last error = %lu, num handles %d, "
                                  "timeout %d",
                                  error, num_wait_handles, ctx->wait_timeout));
        }

      /* Wait failed but we had unregistered events in our system. We
         just run the event loop a round, and the unregistered events
         will be removed in the beginning of the event loop. */
      ssh_mutex_lock(thread_data_lock);

#ifdef DEBUG_LIGHT
      {
        int i;
        /* Let's print out which handle was invalid, if any. */
        for (i=0; i < num_wait_handles; i++)
        {
          DWORD d = WaitForSingleObject(wait_handles[i], 1);
          if (d == WAIT_FAILED)
            SSH_DEBUG(1, ("Invalid handle in event loop! Handle = %p, "
                          "last err = %x",
                          wait_handles[i], GetLastError()));
        }
      }
#endif /* DEBUG_LIGHT */

      if (!thread_signaled)
        {
          /* This thread was first to wake up. We have to report that
             wait was abandoned. */
          thread_return_value = SSH_WAIT_ABANDONED;
          thread_event_handle = 0;
        }
      else
        {
          /* This thread was not first thread to report. We do not have
             to report anything to the main event loop thread. */
        }
      ssh_mutex_unlock(thread_data_lock);
        goto thread_done;
    }

  if (result == WAIT_TIMEOUT)
    result = SSH_WAIT_TIMEOUT;
#ifndef _WIN32_WCE
  else if (result == WAIT_IO_COMPLETION)
    result = SSH_WAIT_IO_COMPLETION;
#endif /* _WIN32_WCE */
  else if (result == (WAIT_OBJECT_0 + num_wait_handles))
  {
    /*
      The wait terminated because of input specified by the mask.
      This means a Windows message is in the thread's message queue.
    */
    result = SSH_WAIT_WINDOWS_MSG;
  }
  else if (result >= WAIT_OBJECT_0 && result <
           WAIT_OBJECT_0 + num_wait_handles)
  {
    signaled_handle_index = result - WAIT_OBJECT_0;
    result = SSH_WAIT_HANDLE;
  }
  else if (result >= WAIT_ABANDONED_0 &&
           result < WAIT_ABANDONED_0 + num_wait_handles)
  {
    signaled_handle_index = result - WAIT_ABANDONED_0;
    result = SSH_WAIT_ABANDONED;
  }
  else
    result = SSH_WAIT_UNKNOWN;

  /* Save the results for the parent thread. Ignore our wakeup
     dummy event. */
  if (!((result == SSH_WAIT_HANDLE || result == SSH_WAIT_ABANDONED) &&
        signaled_handle_index == num_wait_handles - 1))
  {
    ssh_mutex_lock(thread_data_lock);

    if (!thread_signaled)
    {
      /* We are the first thread to wake. Let's store the result
         into simple variables instead of lists. */
      thread_signaled = TRUE;

      thread_return_value = result;
      if (result == SSH_WAIT_HANDLE || result == SSH_WAIT_ABANDONED)
        thread_event_handle = wait_handles[signaled_handle_index];

      /* signal all waiting threads to stop */
      SetEvent(thread_wake_handle);
    }
    else
    {
      /* We are not the first thread, let's store the result
         into list. */
      SshWaitResult val = ssh_xmalloc(sizeof(*val));
      val->result = result;
      if (result == SSH_WAIT_HANDLE || result == SSH_WAIT_ABANDONED)
        val->event_handle = wait_handles[signaled_handle_index];

      ssh_adt_insert_to(ssh_eloop_wait_return_values, SSH_ADT_END, val);
    }

    ssh_mutex_unlock(thread_data_lock);
  }

thread_done:
  if (ctx->free_context)
    ssh_xfree(ctx);
  return NULL;
}

/* Returns wait results from the list. Wait results are in a list
   if multiple threads got signaled during previous wait. */
BOOL ssh_event_get_previous_wait_results(int *result, HANDLE *event_handle)
{
  SshADTHandle list_item;

  if (ssh_eloop_wait_return_values == NULL)
    return FALSE;

  ssh_mutex_lock(thread_data_lock);

  /* get first item and delete it */
  list_item = ssh_adt_enumerate_start(ssh_eloop_wait_return_values);
  if (list_item != SSH_ADT_INVALID)
  {
    SshWaitResult val;
    val = ssh_adt_get(ssh_eloop_wait_return_values, list_item);
    *result = val->result;
    *event_handle = val->event_handle;
    ssh_adt_delete(ssh_eloop_wait_return_values, list_item);
    ssh_xfree(val);

    SSH_DEBUG(SSH_D_MIDRESULT,
              ("returning previous waiting result %d",
               *result));
    ssh_mutex_unlock(thread_data_lock);

    return TRUE;
  }

  ssh_mutex_unlock(thread_data_lock);
  return FALSE;
}

void ssh_event_remove_event_from_wait_results(HANDLE event_handle)
{
  SshADTHandle list_item;

  if (ssh_eloop_wait_return_values == NULL)
    return;

  list_item = ssh_adt_enumerate_start(ssh_eloop_wait_return_values);
  while (list_item != SSH_ADT_INVALID)
  {
    SshWaitResult val = ssh_adt_get(ssh_eloop_wait_return_values, list_item);
    if (val->event_handle == event_handle)
    {
      ssh_adt_delete(ssh_eloop_wait_return_values, list_item);
      ssh_xfree(val);
      return;
    }

    list_item = ssh_adt_enumerate_next(ssh_eloop_wait_return_values,
                                       list_item);
  }
}

/* Main wait function that waits for unlimited number of events.
   Takes care of dividing the waiting for multiple threads if
   necessary. */
int ssh_event_wait_for_events(int num_wait_handles,
        SshADTContainer event_list,
        DWORD wait_timeout, HANDLE *signaled_handle)
{
  int result;
  int i = 0;
  int j, k;
  SshWaitContextStruct ctx_stack;
  int thread_count = 0;
  int block_count;
  SshEvent event;
  SshADTHandle list_item;

  SSH_DEBUG(SSH_D_MIDRESULT,
            ("waiting for %d events: timeout %u",
             num_wait_handles,(unsigned int)wait_timeout));

  /* First we must check if in the previous call multiple waiting threads got
     signaled at the same time. If it did happen, their results are in a list.
     */
  if (ssh_event_get_previous_wait_results(&result, signaled_handle))
    return result;


  list_item = ssh_adt_enumerate_start(event_list);

  /* reset parent book keeping data */
  thread_signaled = FALSE;
  ResetEvent(thread_wake_handle);

  /* we must create this many threads */
  block_count = num_wait_handles / SSH_MAXIMUM_REAL_WAIT_OBJECTS;

  /* let's create a thread for each SSH_MAXIMUM_REAL_WAIT_OBJECTS events */
  for (k = 0; k < block_count; k++)
  {
    SshWaitContext ctx;

    ctx = ssh_xmalloc(sizeof(*ctx));
    ctx->wait_timeout = wait_timeout;

    /* A thread can wait at most SSH_MAXIMUM_REAL_WAIT_OBJECTS events. */
    ctx->handle_count = SSH_MAXIMUM_REAL_WAIT_OBJECTS;

    /* fill the array with event handles */
    for (j=0; j < ctx->handle_count; j++)
    {
      /* at this point, there are no unregisted events in the list */
      event = ssh_adt_get(event_list, list_item);
      if (!event->unregistered)
        ctx->handles[j] = event->hevent;
      else
        ctx->handles[j] = thread_wake_handle;
      list_item = ssh_adt_enumerate_next(event_list, list_item);
    }

    ctx->take_all_input = FALSE;
    ctx->free_context = TRUE;

    /* get a thread from pool and launch it */
    ssh_thread_pool_start(ssh_eloop_thread_pool, TRUE,
                          ssh_event_thread_wait_for_events, ctx);

    /* take next wait handles */
    i += SSH_MAXIMUM_REAL_WAIT_OBJECTS;
    thread_count++;
  }

  /* we take the rest of the events and go to wait as well */
  ctx_stack.handle_count = (num_wait_handles - i);
  ctx_stack.wait_timeout = wait_timeout;
  for (j=0; j < ctx_stack.handle_count; j++)
  {
    event = ssh_adt_get(event_list, list_item);
    ctx_stack.handles[j] = event->hevent;
    list_item = ssh_adt_enumerate_next(event_list, list_item);
  }
  ctx_stack.take_all_input = TRUE;
  ctx_stack.free_context = FALSE;
  ssh_event_thread_wait_for_events(&ctx_stack);

  /* our wait finished, some thread returned results */

  /* return the wait results */
  *signaled_handle = thread_event_handle;
  return thread_return_value;
}
/* === WAITING FOR EVENTS WITH THREADS === */


/*
*/
static Boolean ssh_event_loop_check_for_termination = TRUE;

void ssh_event_loop_dont_check_termination()
{
  ssh_event_loop_check_for_termination = FALSE;
}

#ifdef _WIN32_WCE
static unsigned _stdcall
#else
static void
#endif /* _WIN32_WCE */
the_event_loop(void* params)
{
  SshEvent event;
  DWORD num_wait_handles;
  int wait_timeout;
  DWORD result;
  SshADTHandle handle;
  HANDLE signaled_handle;

  app_thread = (DWORD)params;
  /* Remember our thread id - ssh_event_loop_abort() needs it to send
     us a WM_QUIT message */
  eloop_thread_id = GetCurrentThreadId();


  ssh_event_loop_running = TRUE;
  ssh_event_loop_lock();

  ssh_eloop_runtime_wait_handles = 0;

  /* SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL); */

  for (;;)
    {
      /* Execute and remove all expired timeout callbacks */
      wait_timeout = ssh_event_loop_do_timeouts();

      num_wait_handles = 0;
      handle = ssh_adt_enumerate_start(ssh_eloop_events);
      while (handle != SSH_ADT_INVALID)
        {
           SshADTHandle tmp = handle;
           handle = ssh_adt_enumerate_next(ssh_eloop_events, handle);
           event = ssh_adt_get(ssh_eloop_events, tmp);

           if (!event->unregistered)
             {
               num_wait_handles++;
             }
           else
             {
              /* This is the only place where event entries will get
                 freed.  We do not want to remove entries in other
                 threads when MsgWaitForMultipleObjects() is active,
                 because that would leave us without underlying
                 context structure when the wait returns.  */
               ssh_adt_delete(ssh_eloop_events, tmp);
             }
        }
      /* Check if the event loop should be exited. A window instance
      counter should be added here.  */
      if (ssh_eloop_runtime_wait_handles == 0 && ssh_eloop_sockets == NULL &&
          wait_timeout == INFINITE && ssh_event_loop_check_for_termination)
          {
            ssh_event_loop_running = FALSE;
            ssh_event_loop_unlock();
#ifdef _WIN32_WCE
            return (ERROR_SUCCESS);
#else
            return;
#endif /* _WIN32_WCE */
          }

      ssh_event_loop_unlock();

      /* Waits for events. Returns the type of the event. If a handle got
         signaled, (return value is SSH_WAIT_HANDLE) its HANDLE is returned
         in 'signaled_handle'. */
      result = ssh_event_wait_for_events(num_wait_handles, ssh_eloop_events,
        wait_timeout, &signaled_handle);

      ssh_event_loop_lock();

      if (result == SSH_WAIT_TIMEOUT)
        {
          /* The wait timed out. Expired timeouts will get processed
             before next wait */
          SSH_DEBUG(SSH_D_MIDRESULT, ("ssh_event_loop_run: timeout"));
          continue;
        }

      if (result == SSH_WAIT_IO_COMPLETION)
        {
          /* Some APC (asynchronous procedure call), such as I/O completion
             callback, has been called, which caused the wait to terminate. */
          SSH_DEBUG(SSH_D_MIDRESULT, ("ssh_event_loop_run: APCs processed"));
          continue;
        }

      if (result == SSH_WAIT_WINDOWS_MSG)
        {
          MSG msg;

          /* Process messages while keeping event loop locked */
          while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
            {
              if (msg.message == WM_QUIT)
                {
                  ssh_event_loop_running = FALSE;
                  ssh_event_loop_unlock();
#ifdef _WIN32_WCE
                  return (ERROR_SUCCESS);
#else
                  return;
#endif /* _WIN32_WCE */
                }

              TranslateMessage(&msg);
              DispatchMessage(&msg);
            }
          continue;
        }

        /* The returned value is in the range of handles being waited.
           This indicates that the handle signaled_handle has a
           result pending. */
        if (result == SSH_WAIT_HANDLE)
          {
            SSH_DEBUG(SSH_D_MIDRESULT,
                      ("input available from handle %08p",
                       signaled_handle));

            handle = ssh_adt_enumerate_start(ssh_eloop_events);
            while (handle != SSH_ADT_INVALID &&
                   (event = ssh_adt_get(ssh_eloop_events, handle)) &&
                    event->hevent != signaled_handle)
              handle = ssh_adt_enumerate_next(ssh_eloop_events, handle);

            if (handle != SSH_ADT_INVALID
                && !event->unregistered
                && event->callback != NULL)
              ssh_eloop_execute_event_callback(app_thread, event);

            /*  */

            continue;
          }

        if (result == SSH_WAIT_ABANDONED)
          {
            SSH_DEBUG(SSH_D_UNCOMMON, ("abandoned wait handle %08p",
                                       signaled_handle));
            continue;
          }

      /* Never reached */
      SSH_DEBUG(0, ("ssh_event_loop_run: unexpected wait status: 0x%08X",
                    result));
      SSH_ASSERT(FALSE);
    }
}

/* Execute the event callback in the proper thread. When using
   ssh_event_loop_run(), timeouts are executed in the same thread
   than the event loop runs, but when using ssh_event_loop_start(),
   a special ssh_eloop_event_msg is sent to the application
   thread, which calls the evet callback. This implementation relies
   on the fact that event structures are not freed from the memory,
   until event loop is stopped. */
static void ssh_eloop_execute_event_callback(DWORD thread,
                                             SshEvent event)
{
  SSH_ASSERT(event->callback != NULL);

  if (thread == GetCurrentThreadId())
    {
      /* We are already in correct thread, just do the callback */
      (*event->callback)(event->context);
    }
  else
    {
      /* Callback executes in the context of other thread and event loop */
      PostMessage(ssh_eloop_hidden_window,
                  ssh_eloop_event_msg, (WPARAM)event, (LPARAM)0);
    }
}


/* Executes the timeout callback in the proper thread. When using
   ssh_event_loop_run(), timeouts are executed in the same thread
   than the event loop runs, but when using ssh_event_loop_start(),
   a special ssh_eloop_timeout_msg is sent to the application
   thread, which calls the timeout callback. */
static void ssh_eloop_execute_timeout_callback(
  DWORD thread,
  SshTimeout timeout)
{
  SSH_ASSERT(timeout->callback != NULL);

  if (thread == GetCurrentThreadId() && ssh_eloop_in_callback == FALSE)
    {
      SshTimeoutCallback callback = timeout->callback;
      void *context = timeout->context;

      SSH_DEBUG(SSH_D_MIDRESULT, ("Execute timeout callback directly"));

      ssh_cancel_timeout(timeout);

      SSH_DEBUG(SSH_D_MY5,
                ("Executing timeout callback %08p (ctx %08p)",
                callback, context));

      ssh_eloop_in_callback = TRUE;
      /* We are already in correct thread, just do the callback */
      (*callback)(context);
      ssh_eloop_in_callback = FALSE;

      SSH_DEBUG(SSH_D_MY5, ("Timeout callback %08p returned", callback));
    }
  else
    {
      /* Callback executes in the context of other thread and event loop.
         Post a message with a timeout ID */
      DWORD wparam;
      DWORD lparam;

      wparam = (DWORD)(timeout->identifier >> 32);
      lparam = (DWORD)(timeout->identifier);

      PostMessage(ssh_eloop_hidden_window,
        ssh_eloop_timeout_msg, wparam, lparam);
    }
}

/* Checks if this is an SSH message. We can queue only our own messages,
   so this checks if the messages is timeout/socket or event message
   and returns TRUE for those. */
Boolean ssh_eloop_is_ssh_message(UINT msg)
{
  if (msg == ssh_eloop_socket_msg)
    return TRUE;
  if (msg == ssh_eloop_event_msg)
    return TRUE;
  if (msg == ssh_eloop_timeout_msg)
    return TRUE;
  if (msg == ssh_eloop_signal_msg)
    return TRUE;
  return FALSE;
}

/* Window procedure for the hidden window.  This will handle the
   SSH_SOCKET_EVENT messages and convert them to callbacks.
   This will also queue events if appropriate. */
static LRESULT CALLBACK ssh_eloop_handle_msg(
  HWND hWnd,
  UINT msg,
  WPARAM wparam,
  LPARAM lparam
)
{
  LRESULT ret = 0;
  ssh_eloop_in_callback = TRUE;
  if (msg == ssh_eloop_socket_msg)
    {
      SshSocket s;
      SshIOHandle sock;
      unsigned error;
      unsigned event;
#ifdef _WIN32_WCE
      LPWSANETWORKEVENTS net_events = (LPWSANETWORKEVENTS)lparam;
#endif /* _WIN32_WCE */

      SSH_DEBUG(SSH_D_MIDRESULT, ("ssh_eloop: Handling socket event"));

      sock = (SshIOHandle)wparam;

#ifdef _WIN32_WCE
      error = 0;
      event = (unsigned)net_events->lNetworkEvents;
      if (event & FD_CONNECT)
        error = net_events->iErrorCode[FD_CONNECT_BIT];
#else
      error = WSAGETSELECTERROR(lparam);
      event = WSAGETSELECTEVENT(lparam);
#endif /* _WIN32_WCE */

      for (s = ssh_eloop_sockets; s && s->sock != sock; s = s->next);

      if (s == NULL)
        {
          SSH_DEBUG(SSH_D_UNCOMMON,
                    ("ssh_eloop_handle_socket_event: no socket found"));
        }
      else if (s->callback != NULL)
        {
           int e = 0;
           if (event & FD_CLOSE)
             {
                e = SSH_IO_CLOSED;
             }
           else
             {
                e |= (event & FD_READ) ? SSH_IO_READ : 0;
                e |= (event & FD_WRITE) ? SSH_IO_WRITE : 0;
                if (e == 0)
                  e = SSH_IO_WRITE;

                /* If we got an error when we tried to connect we pass
                   an SSH_IO_CLOSED to the event callback. */
                if (event & FD_CONNECT && error != 0)
                  e = SSH_IO_CLOSED;
             }

          s->callback(e, s->context);
        }
    }
  else if (msg == ssh_eloop_event_msg)
    {
      SshEvent event = (SshEvent)wparam;

      if (!event->unregistered && event->callback)
        (*event->callback)(event->context);
    }
  else if (msg == ssh_eloop_timeout_msg)
    {
      /* Handle timeouts. */
      SshTimeout timeout;
      SshTimeoutStruct tmp_timeout;
      SshADTHandle mh;

      SshUInt64 id = ((SshUInt64)wparam << 32) + lparam;
      tmp_timeout.identifier = id;
      mh = ssh_adt_get_handle_to_equal(ssheloop.to.map_by_identifier,
                                       &tmp_timeout);
      if (mh != SSH_ADT_INVALID)
        {
          SshTimeoutCallback callback;
          void *context;
          timeout = ssh_adt_get(ssheloop.to.map_by_identifier,  mh);

          SSH_ASSERT(timeout != NULL);
          callback = timeout->callback;
          context = timeout->context;
          ssh_cancel_timeout(timeout);
          if (callback)
            (*callback)(context);
        }
      else
        {
          /* Nothing here. The timeout has been cancelled */
        }
    }
  else if (msg == ssh_eloop_signal_msg)
    {
      /* Signal emulation for Windows CE. */
      ssh_eloop_signal_handler((void *)wparam);
    }
  else
    {
      ret = DefWindowProc(hWnd, msg, wparam, lparam);
    }

  ssh_eloop_in_callback = FALSE;
  return ret;
}

void ssh_eloop_process_queued_messages(void)
{
  /* Process all the queued messages */
  SshADTHandle handle, nhandle;
  handle = ssh_adt_enumerate_start(ssh_eloop_queued_msgs);
  while (handle!= SSH_ADT_INVALID)
  {
    SshQueuedMsg msg =
      (SshQueuedMsg)ssh_adt_get(ssh_eloop_queued_msgs,
                                  handle);

    /* Process a queued event. */
    ssh_eloop_handle_msg(msg->hWnd, msg->msg,
                         msg->wparam, msg->lparam);
    ssh_xfree(msg);

    nhandle = ssh_adt_enumerate_next(ssh_eloop_queued_msgs,
                                    handle);

    ssh_adt_delete(ssh_eloop_queued_msgs, handle);
    handle = nhandle;
  }
}

static LRESULT CALLBACK ssh_eloop_window_proc(
  HWND hWnd,
  UINT msg,
  WPARAM wparam,
  LPARAM lparam
)
{
  LRESULT ret = 0;

  ssh_event_loop_lock();
  if (!ssh_eloop_is_ssh_message(msg))
        {
    /* Handle a non SSH message and quit. */
          ret = ssh_eloop_handle_msg(hWnd, msg, wparam, lparam);
    ssh_event_loop_unlock();
    return ret;
        }

  if (ssh_eloop_in_callback)
  {
    /* Add the message to a queue and process it later. */
    SshQueuedMsg qmsg = ssh_xcalloc(1, sizeof(*qmsg));
    qmsg->hWnd = hWnd;
    qmsg->msg = msg;
    qmsg->wparam = wparam;
    qmsg->lparam = lparam;

    ssh_adt_insert_to(ssh_eloop_queued_msgs,
        SSH_ADT_END, qmsg);

    ssh_event_loop_unlock();
    return 0;
  }
  else
  {
    /* Process all the queued messages */
    ssh_eloop_process_queued_messages();
  }

  /* Handle the message in question. */
  ret = ssh_eloop_handle_msg(hWnd, msg, wparam, lparam);
  /* During the above callback, we may have been come here
     (ssh_eloop_window_proc()) again so there may be queued events
     in the queue. Let's process them before we leave here. */
  ssh_eloop_process_queued_messages();
  ssh_event_loop_unlock();
  return ret;
}

/* The event loop guarantees that only one callback is running at any
   one time.  If any callbacks (in the same "domain" as the callbacks
   called by the event loop) are called from other threads, they must
   call this function to lock the event loop.  This function essentially
   takes a mutex that is locked by the event loop whenever it is running
   in a callback.  Holding this lock ensures that no other callbacks will
   be running in parallel.  This call will block until the callback
   mutex has been obtained.  Also, functions related to the event loop
   cannot be called from other threads (i.e., from somewhere other than
   a callback) without taking this first.  Beware, however, that calling
   this function twice without first releasing the lock will cause the
   application to hang. */

void ssh_event_loop_lock()
{
  EnterCriticalSection(&ssh_eloop_lock);
}


/* This function releases the event loop mutex, allowing other callbacks
   to be executed. */

void ssh_event_loop_unlock()
{
  LeaveCriticalSection(&ssh_eloop_lock);
}

void ssh_event_loop_lock_timeouts()
{
  EnterCriticalSection(&ssh_eloop_timeout_lock);
}

void ssh_event_loop_unlock_timeouts()
{
  LeaveCriticalSection(&ssh_eloop_timeout_lock);
}



/*****************************************************************************
 * Timers
 ****************************************************************************/

static void WINAPI ssh_event_loop_apc(DWORD param)
{
  ;
}


/* Internal timeout registering workhorse. External API is below. */
SshTimeout
ssh_register_timeout_internal(SshTimeout timeout,
                              long seconds, long microseconds,
                              SshTimeoutCallback callback, void *context)
{
  SshTimeout created = timeout, p;
  SshADTHandle handle;

  if (seconds > 1000000000)
    {
      seconds = 1000000000;
      microseconds = 0;
    }
  else
    {
      seconds += microseconds / 1000000L;
      microseconds %= 1000000L;
    }

  /* Convert to absolute time and initialize timeout record. */
  ssh_eloop_convert_relative_to_absolute(seconds, microseconds,
                                         &timeout-> firing_time);
  created->callback = callback;
  created->context = context;

  /* Insert the new timeout in the sorted list of timeouts. */
  ssh_event_loop_lock_timeouts();

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

  ssh_event_loop_unlock_timeouts();

  SSH_DEBUG(SSH_D_LOWOK, ("Timeout registered at %x, cb=%08p, ctx=%08p",
                          timeout->firing_time.tv_sec,
                          callback, context));

  /* Wake up the event loop thread. */
  SetEvent(ssh_dummy_event);

  return timeout;
}

/* Registers a timeout function that is to be called once when the
   specified time has elapsed.  The time may be zero, in which case
   the callback will be called as soon as possible from the bottom of
   the event loop.  There is no guarantee about the order in which
   callbacks with zero timeouts are delivered.

   The timeout will be delivered approximately after the specified
   time.  The exact time may differ somewhat from the specified time.
   The timeout will be delivered from the bottom of the event loop
   (i.e., it will be delayed if another callback from the event loop
   is being executed).

   The arguments are as follows:
     seconds        number of full seconds after which the timeout is delivered
     microseconds   number of microseconds to add to full seconds
                    (this may be larger than 1000000, meaning several seconds)
     callback       the callback function to call
     context        context argument to pass to callback function. */

SshTimeout
ssh_xregister_timeout(long seconds, long microseconds,
                      SshTimeoutCallback callback, void *context)
{
  SshTimeout created;

  ssh_event_loop_lock_timeouts();
  TIMEOUT_FREELIST_GET(created, ssheloop.timeout_freelist);

  if (created == NULL)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
       ("Timeout freelist empty, allocating new entry"));
      created = ssh_xmalloc(sizeof(*created));
      if (created == NULL)
        {
          ssh_event_loop_unlock_timeouts();
          ssh_fatal("Insufficient memory available to create timeout.");
        }
    }

  memset(created, 0, sizeof(*created));
  created->is_dynamic = TRUE;
  ssh_event_loop_unlock_timeouts();

  return ssh_register_timeout_internal(created, seconds, microseconds,
                                       callback, context);
}

SshTimeout
ssh_register_timeout(SshTimeout timeout,
                     long seconds, long microseconds,
                     SshTimeoutCallback callback, void *context)
{
  if (timeout != NULL)
    {
      memset(timeout, 0, sizeof(*timeout));
      timeout->is_dynamic = FALSE;
    }
  else
    {
      /* Use the freelist and get the timeout */
      ssh_event_loop_lock_timeouts();
      TIMEOUT_FREELIST_GET(timeout, ssheloop.timeout_freelist);

      if (timeout == NULL)
        {
          timeout = ssh_xmalloc(sizeof(*timeout));
          if (timeout == NULL)
            {
              ssh_event_loop_unlock_timeouts();
              SSH_DEBUG(SSH_D_FAIL,
                    ("Insufficient memory to allocate timeout."));
              return NULL;
            }
        }

      memset(timeout, 0, sizeof(*timeout));
      timeout->is_dynamic = TRUE;

      ssh_event_loop_unlock_timeouts();
    }

  return ssh_register_timeout_internal(timeout, seconds, microseconds,
                                       callback, context);
}

/* Registers an idle timeout function.  An idle timeout will be called once
   when the system has been sufficiently idle for the specified amount of
   time.  The definition of idle is somewhat implementation-dependent, but
   typically means when it is a good time to perform cpu-intensive operations.
   There is no guarantee that the idle timeout ever gets called.  Idle timeouts
   are always delivered from the bottom of the event loop.

   The arguments are as follows:
     seconds        number of seconds the system must be idle before delivering
     microseconds   number of microseconds to add to full seconds
     (this may be larger than 1000000, meaning several seconds)
     callback       the callback function to call
     context        context argument to pass to callback function. */

SshTimeout
ssh_xregister_idle_timeout(long seconds, long microseconds,
                           SshTimeoutCallback callback, void *context)
{
  SSH_TRACE(SSH_D_NICETOKNOW, ("Idle timeouts not yet implemented."));







  return NULL;
}

void
ssh_cancel_timeout(SshTimeout timeout)
{
  SshTimeout p;
  SshADTHandle mh, ph, cmh;

  if (timeout == NULL)
    return;

  ssh_event_loop_lock_timeouts();

  if ((mh =
       ssh_adt_get_handle_to_equal(ssheloop.to.map_by_identifier, timeout))
      != SSH_ADT_INVALID)
    {
      p = ssh_adt_get(ssheloop.to.map_by_identifier, mh);

      SSH_DEBUG(SSH_D_MIDOK, ("cancelled %qd", p->identifier));

      if (!timeout->platform.os_win32.is_expired)
        {
          ph = &p->adt_ft_ph_hdr;
          ssh_adt_detach(ssheloop.to.ph_by_firing_time, ph);
        }

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
        {
          TIMEOUT_FREELIST_PUT(p, ssheloop.timeout_freelist);
        }
      else
        memset(p, 0, sizeof(*p));

      ssh_event_loop_unlock_timeouts();
      return;
    }

  ssh_event_loop_unlock_timeouts();
}

/* Cancel all timeouts that call `callback' with context `context'.
   SSH_ALL_CALLBACKS and SSH_ALL_CONTEXTS can be used as wildcards. */
void ssh_cancel_timeouts(SshTimeoutCallback callback, void *context)
{
  SshADTHandle nmh, mh, cmh;
  SshTimeoutStruct probe;

  ssh_event_loop_lock_timeouts();

  if (context != SSH_ALL_CONTEXTS)
    {
      /* Cancel with given context. */
      probe.context = context;
      if ((cmh =
           ssh_adt_get_handle_to_equal(ssheloop.to.map_by_context, &probe))
          != SSH_ADT_INVALID)
        {
          ssh_to_remove_from_contextmap(&ssheloop.to, callback, context, cmh);
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

  ssh_event_loop_unlock_timeouts();

  /* Wake up the event loop thread (the event loop might be waiting
     for this timeout. */
  SetEvent(ssh_dummy_event);
}


static int ssh_event_loop_do_timeouts(void)
{
  SshTimeout current_timeout = NULL;
  struct timeval now;
  long us, ms;
  SshADTHandle ph;


  /* Execute all expired timeout callbacks */
  ssh_eloop_get_current_time(&now);

  ssh_event_loop_lock_timeouts();

  ph = ssh_adt_get_handle_to_location(ssheloop.to.ph_by_firing_time,
                                      SSH_ADT_DEFAULT);
  while (ph != SSH_ADT_INVALID)
    {
      current_timeout = ssh_adt_get(ssheloop.to.ph_by_firing_time, ph);

      /* Compute time left before the firing time. */
      ms = current_timeout->firing_time.tv_sec - now.tv_sec;
      us = current_timeout->firing_time.tv_usec -
        now.tv_usec;

      /* Catch bad firing times (e.g. zero) causing large negative ms */
      if (ms < 0)
        ms = -1;

      if (us < 0)
        {
          ms--;
          us += 1000000L;
          SSH_ASSERT(us >= 0 && us < 1000000L);
        }
      ms = 1000 * ms + us / 1000;

      if (ms > 0)
        {
          ssh_event_loop_unlock_timeouts();
          return ms;
        }
      current_timeout->platform.os_win32.is_expired = 1;

      ssh_adt_detach(ssheloop.to.ph_by_firing_time, ph);
      ssh_event_loop_unlock_timeouts();
      ssh_eloop_execute_timeout_callback(app_thread, current_timeout);
      ssh_event_loop_lock_timeouts();

      ph = ssh_adt_get_handle_to_location(ssheloop.to.ph_by_firing_time,
                                          SSH_ADT_DEFAULT);
    }

  ssh_event_loop_unlock_timeouts();

  return INFINITE;
}

static void ssh_eloop_get_current_time(struct timeval *tv)
{
#ifdef _WIN32_WCE
  /* Copied from winim ssh_interceptor_get_time() */
  LARGE_INTEGER system_time;
  SYSTEMTIME st;
  FILETIME ft;

  GetSystemTime(&st);
  SystemTimeToFileTime(&st, &ft);
  system_time.HighPart = ft.dwHighDateTime;
  system_time.LowPart  = ft.dwLowDateTime;

  system_time.QuadPart /= 10; /* Convert to microseconds */

  tv->tv_sec = (long)(system_time.QuadPart / 1000000);
  tv->tv_usec = (long)(system_time.QuadPart % 1000000);
#else
  struct _timeb tb;
  _ftime(&tb);

  tv->tv_sec = (long) tb.time;
  tv->tv_usec = 1000 * tb.millitm;
#endif /* _WIN32_WCE */

  ssh_timeout_container_check_clock_jump(&ssheloop.to, tv);
}


/* Convert relative timeout to absolute. */

static void ssh_eloop_convert_relative_to_absolute(long seconds,
                                                   long microseconds,
                                                   struct timeval *timeval)
{
  /* Move full seconds from microseconds to seconds. */
  seconds += microseconds / 1000000L;
  microseconds %= 1000000L;

  /* Get current time. */
  ssh_eloop_get_current_time(timeval);

  /* Add current time to the specified time. */
  timeval->tv_sec += seconds;
  timeval->tv_usec += microseconds;
  if (timeval->tv_usec > 999999L)
    {
      timeval->tv_usec -= 1000000L;
      timeval->tv_sec++;
    }
}

/* Signal handlers */

static void ssh_eloop_signal_handler(void *context)
{
  int signal_num = (int)context;
  SshSignal ssh_signal = NULL;
  SshADTHandle handle;

  SSH_DEBUG(SSH_D_MIDRESULT, ("Received signal %d.", signal_num));

  /* Check if the signal has been registered earlier un unregister earlier
     registerations. */
  handle = ssh_adt_enumerate_start(ssh_eloop_signals);
  while (handle != SSH_ADT_INVALID)
    {
      ssh_signal = ssh_adt_get(ssh_eloop_signals, handle);
      if (ssh_signal && ssh_signal->signal == signal_num
          && !ssh_signal->unregistered && ssh_signal->callback)
          (*ssh_signal->callback)(signal_num, ssh_signal->context);
     handle = ssh_adt_enumerate_next(ssh_eloop_signals, handle);
    }
}

void ssh_eloop_signal_callback(int signal_num)
{
  ssh_register_threaded_timeout(NULL,
                                0, 0,
                                ssh_eloop_signal_handler,
                                (void *)signal_num);
#ifndef _WIN32_WCE
  signal(signal_num, ssh_eloop_signal_callback);
#endif /* _WIN32_WCE */
}

/* Registers the specified callback function to be called from the
   bottom of the event loop whenever the given signal is received.
   The registration will remain in effect until explicitly
   unregistered.  If the same signal is received multiple times before
   the callback is called, the callback may get called only once for
   those multiple signals.  The `callback' argument may be NULL, in
   which case the signal will be ignored. */

void ssh_register_signal(int signal_num, SshSignalCallback callback,
                         void *context)
{
  SshSignal ssh_signal = NULL;
  SshADTHandle handle;

  /* Check if the signal has been registered earlier un unregister earlier
     registerations. */
  handle = ssh_adt_enumerate_start(ssh_eloop_signals);
  while (handle != SSH_ADT_INVALID)
    {
      SshADTHandle tmp = handle;
      ssh_signal = ssh_adt_get(ssh_eloop_signals, tmp);
      handle = ssh_adt_enumerate_next(ssh_eloop_signals, handle);
      if (ssh_signal &&
          ssh_signal->signal == signal_num)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Signal reregistered"));
          ssh_adt_delete(ssh_eloop_signals, tmp);
          ssh_xfree(ssh_signal);
        }
    }

  ssh_signal = ssh_xcalloc(1, sizeof(*ssh_signal));
  ssh_signal->callback = callback;
  ssh_signal->context = context;
  ssh_signal->signal = signal_num;

  ssh_adt_insert_to(ssh_eloop_signals, SSH_ADT_END, ssh_signal);

#ifndef _WIN32_WCE
  signal(signal_num, ssh_eloop_signal_callback);
#endif /* _WIN32_WCE */

  return;
}


/* Restores the handling of the signal to the default behavior.  Any
   callback registered for the signal will no longer be called (even
   if the signal has already been triggered, but the callback has not
   yet been called, it is guaranteed that the callback will not get
   called for the signal if this has been called before it is
   delivered).  Note that this function restores the signal to default
   behavior (e.g., core dump), whereas setting the callback to NULL
   causes the signal to be ignored. */
void ssh_unregister_signal(int signal_num)
{
  SshSignal ssh_signal = NULL;
  SshADTHandle handle;
  SSH_DEBUG(SSH_D_MIDRESULT, ("Unregistering signal %d.", signal_num));

  /* Check if the signal has been registered earlier un unregister earlier
     registerations. */
  handle = ssh_adt_enumerate_start(ssh_eloop_signals);
  while (handle != SSH_ADT_INVALID)
    {
      ssh_signal = ssh_adt_get(ssh_eloop_signals, handle);
      if (ssh_signal && ssh_signal->signal == signal_num)
        break;
     handle = ssh_adt_enumerate_next(ssh_eloop_signals, handle);
    }

  if (ssh_signal != NULL)
    ssh_adt_delete_object(ssh_eloop_signals, ssh_signal);

  ssh_xfree(ssh_signal);
#ifndef _WIN32_WCE
  signal(signal_num, SIG_DFL);
#endif /* _WIN32_WCE */
  return;
}


/* Waitable handle registration */
void ssh_event_loop_register_handle(HANDLE hevent,
                                    Boolean manual_reset,
                                    SshEventCallback callback,
                                    void *context)
{
  SshEvent event;

  SSH_DEBUG(SSH_D_MIDRESULT,
            ("Registering new handle %08p, handle count before %d", hevent,
             ssh_adt_num_objects(ssh_eloop_events)));

  if (hevent == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Trying to register NULL handle."));

      SetEvent(ssh_dummy_event);
      return;
    }

  event = ssh_adt_get(ssh_eloop_events, ssh_adt_alloc(ssh_eloop_events));
  event->hevent = hevent;
  event->callback = callback;
  event->context = context;
  event->unregistered = FALSE;

  if (ssh_event_loop_running)
    ssh_eloop_runtime_wait_handles++;

  SetEvent(ssh_dummy_event);
}


void ssh_event_loop_unregister_handle(HANDLE hevent)
{
  SshADTHandle handle;
  SshEvent event;

  SSH_DEBUG(SSH_D_MIDRESULT, ("Unregistering handle %08p", hevent));

  if (hevent == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Unregister handle called with invalid "
                                   "parameter."));
      return;
    }

  ssh_event_loop_lock();

  handle = ssh_adt_enumerate_start(ssh_eloop_events);
  for (; handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(ssh_eloop_events, handle))
    {
       event = ssh_adt_get(ssh_eloop_events, handle);
       if (event->hevent == hevent && !event->unregistered)
         {
           event->unregistered = TRUE;
           break;
         }
    }

  if (ssh_event_loop_running)
    ssh_eloop_runtime_wait_handles--;

  /* remove the event also from the list of thread wait results */
  ssh_event_remove_event_from_wait_results(hevent);

  ssh_event_loop_unlock();
}


/**************************** Socket I/O *********************************/

/* Registers the given file descriptor for the event loop.  This sets
   the descriptor in non-blocking mode, and registers the callback for
   the file descriptor.  Initially, no events will be requested, and
   ssh_socket_set_request must be called before any events will be
   delivered. */

void ssh_io_xregister_fd(SshIOHandle fd, SshIoCallback callback, void *context)
{
  if (ssh_io_register_fd(fd, callback, context) == FALSE)
    ssh_fatal("Insufficient memory available to register file descriptor.");
}

Boolean
ssh_io_register_fd(SshIOHandle fd, SshIoCallback callback, void *context)
{
  SshSocket s;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_io_register_fd(fd = %08p)", fd));

  s = ssh_calloc(1, sizeof(*s));

  if (s == NULL)
    return FALSE;

#ifdef _WIN32_WCE
  /* Windows CE doesn't support WSAAsyncSelect() so we need to use a event
     object for signalling. */
  s->hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (s->hevent == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create event object"));
      ssh_free(s);
      return FALSE;
    }
  ssh_event_loop_register_handle(s->hevent, FALSE,
                                 ssh_io_fd_complete, (void *)fd);
#endif /* _WIN32_WCE */

  s->sock = fd;
  s->callback = callback;
  s->context = context;
  s->next = NULL;

  s->next = ssh_eloop_sockets;
  ssh_eloop_sockets = s;

  return TRUE;
}


/* This removes all socket messages for given socket that have
   already arrived to our event loop. */
static void ssh_event_loop_remove_sock_messages(SshIOHandle sock)
{
  static SshADTContainer socket_msg_list;
  MSG msg;
  SshADTHandle handle;

  socket_msg_list = ssh_adt_create_generic(SSH_ADT_LIST,
                                           SSH_ADT_ARGS_END);

  /* Now get all the socket messages into a queue. Note that we ignore the
     socket messages for the unregistered socket. */
  while (PeekMessage(&msg, ssh_eloop_hidden_window,
                     ssh_eloop_socket_msg, ssh_eloop_socket_msg,
                     PM_REMOVE))
    {
      if (msg.wParam != sock)
        {
          MSG *pmsg = ssh_xmemdup(&msg, sizeof(msg));
          ssh_adt_insert_to(socket_msg_list, SSH_ADT_END, pmsg);
        }
    }


  /* Send valid socket messages back to the queue. */
  handle = ssh_adt_enumerate_start(socket_msg_list);
  while (handle != SSH_ADT_INVALID)
    {
       MSG *pmsg;
       SshADTHandle tmp = handle;
       handle = ssh_adt_enumerate_next(socket_msg_list, handle);
       pmsg = ssh_adt_get(socket_msg_list, tmp);

       PostMessage(ssh_eloop_hidden_window, pmsg->message,
                   pmsg->wParam, pmsg->lParam);
       ssh_adt_delete(socket_msg_list, tmp);
       ssh_xfree(pmsg);
    }

  ssh_adt_destroy(socket_msg_list);
}

/* Cancels any callbacks registered for the file descriptor.  The blocking mode
   of the file descriptor will be restored to its original value.  It is
   guaranteed that no more callbacks will be received for the file descriptor
   after this fucntion has been called. */

void ssh_io_unregister_fd(SshIOHandle sock, Boolean keep_nonblocking)
{
  SshSocket s, *sp;

  /* Find the socket in the list. */
  for (sp = &ssh_eloop_sockets; *sp && (*sp)->sock != sock; sp = &(*sp)->next);

  /* If not found, return with a warning. */
   if (!*sp)
    {
      ssh_warning("ssh_socket_unregister: socket %08p not found", sock);
      return;
    }

  /* Remove the socket from the list. */
  s = *sp;
  *sp = s->next;

#ifdef _WIN32_WCE
  /* Cancel the associationg between network events and the socket. */
  WSAEventSelect(s->sock, s->hevent, 0);
  ssh_event_loop_unregister_handle(s->hevent);
  CloseHandle(s->hevent);
#else
  /* Cancel any events for the socket. */
  WSAAsyncSelect(s->sock, ssh_eloop_hidden_window, 0, 0);
#endif /* _WIN32_WCE */

  /* Check if there are any messages for this socket in the queue
     and remove all ssh_socket_messages for this socket. */
  ssh_event_loop_remove_sock_messages(s->sock);

  /* Free the data structure. */
  ssh_xfree(s);
}

#ifdef _WIN32_WCE

/* This is a callback for a signaled socket event */
static void ssh_io_fd_complete(void *context)
{
  int fd = (int)context;
  WSANETWORKEVENTS events;
  SshSocket s;
  unsigned error = 0;
  unsigned event = 0;
  int e = 0;

  SSH_DEBUG(SSH_D_MIDRESULT, ("ssh_eloop: Handling socket event"));

  /* Look for the indicated socket */
  for (s = ssh_eloop_sockets; s && s->sock != fd; s = s->next)
    {};

  if (s == NULL)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("ssh_io_fd_complete: No socket found!"));
    }
  else
    {
      /* Get network events that have occurred for the indicated socket AND
         reset the associated event object. */
      WSAEnumNetworkEvents(fd, s->hevent, &events);

      /* Post a message to a hidden window. From here the execution flow is
         the same as for non-WinCE platforms which use WSAAsyncSelect(). */
      SendNotifyMessage(ssh_eloop_hidden_window, ssh_eloop_socket_msg,
                        (WPARAM)fd, (LPARAM)&events);
    }
}

#endif /* _WIN32_WCE */


/* Specifies the types of events for which callbacks are to be delivered for
   the file descriptor.  The `events' argument is a bitwise-or of the
   SSH_IO_ values defined above.  If SSH_IO_READ is included, the callback
   will be called whenever data is available for reading.  If SSH_IO_WRITE
   is specified, the callback will be called whenever more data can be
   written to the file descriptor.  Callbacks will continue to be delivered
   from the event loop until the event is either removed from the request
   or the condition causing the event to trigger ceases to exist (e.g., via
   reading all buffered data from a socket). */

void ssh_io_set_fd_request(SshIOHandle fd, unsigned int events)
{
  int ret;
#ifdef _WIN32_WCE
  SshSocket s;

  /* Look for the requested socket */
  for (s = ssh_eloop_sockets; s && s->sock != fd; s = s->next)
    {};

  if (s == NULL)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("ssh_io_set_fd_request: No socket found!"));
      return;
    }

  ret = WSAEventSelect(fd, s->hevent, events);
#else

  ret = WSAAsyncSelect(fd, ssh_eloop_hidden_window,
                       ssh_eloop_socket_msg, events);
#endif /* _WIN32_WCE */

  if (ret != 0)
    SSH_DEBUG(SSH_D_FAIL, ("ssh_io_set_fd_request() failed %d, %d",
                           ret, WSAGetLastError()));
}


/*
  Proxy function for converting the generic SshEventLoopCallbacks to
  SshIoCallbacks.
*/

static void ssh_io_callback_proxy(void* context)
{
  SshIoCallbackParams params = (SshIoCallbackParams)context;

  SSH_ASSERT(params->callback != NULL);
  params->callback(params->events, params->context);

  ssh_xfree(context);
}

#endif /* _WIN32_WCE */
