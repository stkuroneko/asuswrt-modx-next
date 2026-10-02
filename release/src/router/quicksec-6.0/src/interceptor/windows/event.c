/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the implementation for event that is used to
   synchronize execution of tasks in multi-threaded environments.
*/

/*-------------------------------------------------------------------------
  INCLUDE FILES
  -------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "engine_alloc.h"
#include "interceptor_i.h"
#include "event.h"
#include "task.h"

/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE    "SshInterceptorEvent"

/*-------------------------------------------------------------------------
  SSH Event Object
  -------------------------------------------------------------------------*/
struct SshEventRec
{
  /* Link entry for keeping events in a list */
  LIST_ENTRY        link;

  /* Event ID */ 
  ULONG             id;

  /* Windows kernel event object */
#if 0
#ifdef _WIN32_WCE
  HANDLE            handle;
#else /* _WIN32_WCE */
  KEVENT            kevent;     
#endif /* _WIN32_WCE */
#endif /* 0 */
  SshOsEvent        os_event;

  /* Event handler function pointer */
  SshEventMethod    event_cb;

  /* Single input argument for event handler function */
  PVOID             context;    

#ifndef _WIN32_WCE
  /* Storage for native kernel event object */
  KEVENT            nt_kevent;
#endif /* _WIN32_WCE */
};

/*-------------------------------------------------------------------------
  EXTERNALS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  GLOBALS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  LOCAL VARIABLES
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  IN-LINE FUNCTIONS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  EXPORTS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  ssh_event_create()
  
  Constructor for event object.

  Arguments:
  event_id - event identifier,
  event_cb - event callback that is executed when event is signalled,
  context - single input argument for event callback.

  Returns:
  SshEvent object if success, otherwise NULL

  Notes:
  -------------------------------------------------------------------------*/
SshEvent
ssh_event_create(unsigned long event_id,
                 SshEventMethod event_cb, 
                 void *context)
{
  SshEvent event_obj = ssh_calloc(1, sizeof(*event_obj));

  if (event_obj == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory!"));
      return NULL;
    }

  event_obj->id = event_id;
  event_obj->event_cb = event_cb;
  event_obj->context = context;

#ifdef _WIN32_WCE
  event_obj->os_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (event_obj->os_event == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to create event (%08x)", GetLastError()));

      ssh_free(event_obj);
      return NULL;
    }
#else 
  event_obj->os_event = &event_obj->nt_kevent;
  KeInitializeEvent(event_obj->os_event, NotificationEvent, FALSE);
#endif /* _WIN32_WCE */

  return event_obj;
}


/*-------------------------------------------------------------------------
  ssh_event_wrap()
  
  "Converts" native OS event object to SshEvent.

  Arguments:
  event_id - event identifier,
  event_cb - event callback that is executed when event is signalled,
  context - single input argument for event callback.

  Returns:
  SshEvent object if success, otherwise NULL

  Notes:
  -------------------------------------------------------------------------*/
SshEvent
ssh_event_wrap(unsigned long event_id,
               SshOsEvent os_event,
               SshEventMethod event_cb, 
               void *context)
{
  SshEvent event_obj = ssh_calloc(1, sizeof(*event_obj));

  if (event_obj == NULL)
    return NULL;

  event_obj->id = event_id;
  event_obj->event_cb = event_cb;
  event_obj->context = context;
  event_obj->os_event = os_event;

  return event_obj;
}

/*-------------------------------------------------------------------------
  ssh_event_destroy()
  
  Destructor for event object.

  Arguments:
  event - SshEvent object

  Returns:
  Notes:
  ------------------------------------------------------------------------*/
void
ssh_event_destroy(SshEvent event_obj)
{
  SSH_ASSERT(event_obj != NULL);
  SSH_ASSERT(event_obj->os_event != NULL);

#ifdef _WIN32_WCE
  CloseHandle(event_obj->os_event);
#endif /* _WIN32_WCE */

  ssh_free(event_obj);
}

/*-------------------------------------------------------------------------
  Sets the given event to signalled state.
  ------------------------------------------------------------------------*/
void __fastcall
ssh_event_signal(SshEvent event_obj)
{
  SSH_ASSERT(event_obj != NULL);
  SSH_ASSERT(event_obj->os_event != NULL);

#ifdef _WIN32_WCE
  SetEvent(event_obj->os_event);
#else
  KeSetEvent(event_obj->os_event, IO_NO_INCREMENT, FALSE);
#endif /* _WIN32_WCE */
}

/*------------------------------------------------------------------------
  Resets the given event.
  ------------------------------------------------------------------------*/
void __fastcall
ssh_event_reset(SshEvent event_obj)
{
  SSH_ASSERT(event_obj != NULL);
  SSH_ASSERT(event_obj->os_event != NULL);

#ifdef _WIN32_WCE
  ResetEvent(event_obj->os_event);
#else
  KeClearEvent(event_obj->os_event);
#endif /* _WIN32_WCE */
}

/*------------------------------------------------------------------------
  Checks if specified event has been signalled.
  ------------------------------------------------------------------------*/
Boolean __fastcall
ssh_event_is_signalled(SshEvent event_obj)
{
  Boolean signalled = FALSE;

  SSH_ASSERT(event_obj != NULL);
  SSH_ASSERT(event_obj->os_event != NULL);

#ifdef _WIN32_WCE
  if (WaitForSingleObject(event_obj->os_event, 0) == WAIT_OBJECT_0)
    signalled = TRUE;
#else
  if (KeReadStateEvent(event_obj->os_event))
    signalled = TRUE;
#endif /* _WIN32_WCE */

  return signalled;
}

/*------------------------------------------------------------------------
  Returns event ID.
  ------------------------------------------------------------------------*/
unsigned long __fastcall
ssh_event_id(SshEvent event_obj)
{
  SSH_ASSERT(event_obj != NULL);

  return event_obj->id;
}

/*------------------------------------------------------------------------
  Waits single event to occur. 
  ------------------------------------------------------------------------*/
__inline Boolean
ssh_event_wait_single(SshEvent event_obj, 
                      SshWCB wcb)
{
#ifdef _WIN32_WCE
  DWORD wait_time = INFINITE;
#else
  NTSTATUS s = STATUS_SUCCESS;
  LARGE_INTEGER t, *pt = &t;
#endif /* _WIN32_WCE */

  SSH_ASSERT(event_obj != NULL);
  SSH_ASSERT(event_obj->os_event != NULL);

#ifdef _WIN32_WCE
  if (wcb)
    wait_time = wcb->wait_time_ms;

  if (WaitForSingleObject(event_obj->os_event, wait_time) != WAIT_OBJECT_0)
    return FALSE;
#else
  if ((wcb == NULL) || (wcb->wait_time_ms == SSH_EVT_WAIT_INFINITE))
    pt = NULL;
  else
    pt->QuadPart = (wcb->wait_time_ms * (-10000));
    
  s = KeWaitForSingleObject(event_obj->os_event, 
                            Executive, KernelMode, FALSE, pt);

  if (!NT_SUCCESS(s))
    return FALSE;
#endif /* _WIN32_WCE */

  ssh_event_reset(event_obj);
  if (event_obj->event_cb != NULL)
    event_obj->event_cb(event_obj->context);

  return TRUE;
}

/*------------------------------------------------------------------------
  Waits multiple events to occur.
  ------------------------------------------------------------------------*/
__inline Boolean
ssh_event_wait_multiple(unsigned long event_cnt,
                        SshEvent *events, 
                        SshWCB wcb)
{
  unsigned int i = 0;
  void *wait_block = NULL;
  SshOsEvent *wait_objects;
#ifdef _WIN32_WCE
  DWORD status;
  DWORD wait_time = INFINITE;
  BOOL wait_all = TRUE;
#else
  NTSTATUS status = STATUS_SUCCESS;
  LARGE_INTEGER t, *pt = &t;
  WAIT_TYPE wait_type = WaitAll;
#endif /* _WIN32_WCE */

  SSH_PRECOND(events != NULL);
  SSH_PRECOND(event_cnt > 0 && event_cnt < SSH_EVT_WAIT_MAX_CNT);
  SSH_PRECOND(wcb != NULL);

#ifdef _WIN32_WCE
  if (wcb->mode == SSH_EVT_WAIT_MODE_ANY)
    wait_all = FALSE;

  if (wcb->wait_time_ms != SSH_EVT_WAIT_INFINITE)
    wait_time = wcb->wait_time_ms;
#else 
  /* Set wait mode */
  if (wcb->mode == SSH_EVT_WAIT_MODE_ANY)
    wait_type = WaitAny;

  /* Calculate wait timeout */
  if (wcb ->wait_time_ms == SSH_EVT_WAIT_INFINITE)
    pt = NULL;
  else
    pt->QuadPart = (wcb->wait_time_ms * (-10000));
    

  /* Allocate memory for wait block if not allready initialized */
  if (!wcb->reserved[1])
    {
      wait_block = wcb->reserved[1] = 
        ssh_calloc(event_cnt, sizeof(KWAIT_BLOCK));

      if (wait_block == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate wait block"));
          return FALSE;
        }
    }
#endif /* _WIN32_WCE */

  /* Allocate memory for objects if not already initialized */
  if (!wcb->reserved[0])
    {
      wait_objects = ssh_calloc(event_cnt, sizeof(events[0]->os_event));
      if (wait_objects == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate memory for objects"));
          ssh_free(wait_block);
          return FALSE;
        }

      wcb->reserved[0] = wait_objects;

      /* Init object array with events that we are interested in */
      for (i = 0; i < event_cnt; i++)
        wait_objects[i] = events[i]->os_event;
    }

  /* Wait for events to occur */
#ifdef _WIN32_WCE
  status = WaitForMultipleObjects(event_cnt, wcb->reserved[0], 
                                  wait_all, wait_time);

  if ((status < WAIT_OBJECT_0)
      || (status >= (WAIT_OBJECT_0 + event_cnt)))
    {
      DWORD error = GetLastError();

      SSH_DEBUG(SSH_D_FAIL, ("Wait failed (%08X, %08X)", status, error));
      return FALSE;
    }
#else
  status = KeWaitForMultipleObjects(event_cnt, 
                                    wcb->reserved[0],
                                    wait_type, 
                                    Executive, 
                                    KernelMode, 
                                    FALSE, 
                                    pt, 
                                    wcb->reserved[1]);

  /* Check wait result */
  if (!NT_SUCCESS(status))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Wait failed (%08X)", status));
      return FALSE;
    }
#endif /* _WIN32_WCE */

  if ((unsigned long)status < event_cnt)
    {
      /* Clear event state */
      ssh_event_reset(events[status]);

      /* Execute possible associated event handler routine */
      if (events[status]->event_cb)
        events[status]->event_cb(events[status]->context);
    }

  return TRUE;
}

/*------------------------------------------------------------------------
  ssh_event_wait()
  
  Wait for specified event to occur.

  Arguments:
  event_cnt - # of events
  event - event array
  wcb - Wait Control Block for OS wait routine
  
  Returns:
  TRUE - success, 
  FALSE - otherwise.
  
  Notes:
  ------------------------------------------------------------------------*/
Boolean __fastcall
ssh_event_wait(SshUInt8 event_cnt,
               SshEvent *events,
               SshWCB wcb)
{
  if (event_cnt == 0)
    return TRUE;

  if (event_cnt == 1)
    return(ssh_event_wait_single(*events, wcb));
  else
    return(ssh_event_wait_multiple(event_cnt, events, wcb));
}

