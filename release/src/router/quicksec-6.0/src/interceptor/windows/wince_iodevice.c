/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic two-directional communications stream between user-mode
   applications and device drivers. Interface to abstract I/O device is
   common between all Windows versions; this is the Windows CE specific
   implementation.
*/

/* #includes */

#ifdef _WIN32_WCE

#include "sshincludes.h"
#include "interceptor_i.h"
#include "iodevice.h"
#include "pktizer.h"
#include <windev.h>

/**************************** Constant Definitions **************************/
#define SSH_DEBUG_MODULE "SshInterceptorIodevice"

/* SSH_IODEVICE_QUEUE_SIZE specifies the maximum amout of waiting messages
   before I/O device begins to drop unreliable messages. */
#ifdef DEBUG_LIGHT
/* You may fine-tune this value for your needs. Value 4000 allows forwarding
   of detailed debug output (without too many "lost" debug messages), but on
   the other hand the memory usage "penalty" is SSH_IODEVICE_QUEUE_SIZE times
   sizeof(SshDeviceBufferRec). (400 * 28 bytes = about 11 kilobytes!) */
#define SSH_IODEVICE_QUEUE_SIZE   400
#else 
/* Release version of interceptor should not need a big read queue. */
#define SSH_IODEVICE_QUEUE_SIZE   20
#endif /* DEBUG_LIGHT */

#define	SSH_INVALID_SEEK          ((DWORD) -1)

#define	FNAME_QUICKSEC            TEXT("quicksec.dll")

/****************************** Type Definitions ****************************/

/* Local types */

typedef struct SshDeviceBufferRec
{
  /* Used to chain segments to the output_queue */
  LIST_ENTRY link;

  /* This entry is used only when the same item is put also to
     the list of unreliable messages. (Optimization) */
  LIST_ENTRY unreliable_list_link;

  /* Pointer to the ssh_malloc'd data */
  unsigned char *addr;

  /* Specifies whether this buffer can be dropped */
  unsigned int reliable:1;
  /* Offset of the data from 'addr' */
  unsigned int offset:31;

  /* Specifies whether this buffer has been pre-allocated (i.e. after
     use it will be inserted back to "free queue") */
  unsigned int pre_allocated:1;
  /* Length of data from 'addr + offset' to the end */
  unsigned int len:31;
} SshDeviceBufferStruct, *SshDeviceBuffer;

typedef struct SshInterceptorIoDeviceRec
{
  /* If true, device is being held open by user-mode process */
  unsigned int open : 1;
  unsigned int cancel_io : 1;

  /* Routine to execute for each successful create- and close-IRP */
  SshInterceptorIoDeviceStatusCB status_cb;

  /* Routine to execute for each successful write-IRP */
  SshInterceptorIoDeviceReceiveCB receive_cb;

  /* Context information used in callbacks */
  void* cb_context;

  /* Packetizer object */
  SshPacketizerStruct pktizer;

  /* Queue and lock for submitted but not yet consumed buffers */
  LIST_ENTRY output_queue;      /* list of waiting SshDeviceBuffers */
  LIST_ENTRY unreliable_output_queue; /* Unreliable items */
  NDIS_SPIN_LOCK output_queue_lock;
  LIST_ENTRY free_list; /* list of free SshDeviceBuffers */
  NDIS_SPIN_LOCK free_list_lock;

  SshDeviceBuffer current_read_buf;

  /* Handle to "QSI1" device */
  HANDLE handle;

  /* Event for waking up a waiting thread */
  HANDLE notify_event;

  /* Critical section object synchronizing read request processing */
  CRITICAL_SECTION read_cs;

  /* Reference count ensuring exclusive access */
  LONG stream_interface_refcount;

  /* Pre-allocated buffer descriptors */
  SshDeviceBufferStruct pre_allocated_buffers[SSH_IODEVICE_QUEUE_SIZE];
};

/********************************* Local Data *******************************/

/*************************** Function Definitions ***************************/
Boolean ssh_interceptor_iodevice_is_open(SshInterceptorIoDevice iodevice) 
{
  return ((iodevice != NULL) && (iodevice->open));
}


__inline SshDeviceBuffer
ssh_iodevice_buffer_alloc(SshInterceptorIoDevice io_dev,
                          Boolean reliable)
{
  SshDeviceBuffer buf = NULL;
  PLIST_ENTRY entry;

  /* 1. Try to get a SshDeviceBuffer from a free list */
  entry = NdisInterlockedRemoveHeadList(&io_dev->free_list,
                                        &io_dev->free_list_lock);
  if (entry)
    buf = CONTAINING_RECORD(entry, SshDeviceBufferStruct, link);

  /* 2. If failed and this is a reliable message, try to replace
     an existing unreliable one */
  if ((buf == NULL) && (reliable))
    {
      NdisAcquireSpinLock(&io_dev->output_queue_lock);
      if (!IsListEmpty(&io_dev->unreliable_output_queue))
        {
          /* We found an existing unreliable message */
          entry = RemoveHeadList(&io_dev->unreliable_output_queue);

          /* We must remove the entry from output_queue too */
          buf = CONTAINING_RECORD(entry, SshDeviceBufferStruct,
                                  unreliable_list_link);

          /* This removes the entry from output_queue */
          RemoveEntryList(&(buf->link));
        }
      NdisReleaseSpinLock(&io_dev->output_queue_lock);

      /* If found, we must delete the old message */
      if (buf != NULL)
        ssh_free(buf->addr);
    }

  /* 3. If still failed, try to allocate memory for a new
     SshDeviceBuffer */
  if ((buf == NULL) && (reliable))
    {
      buf = ssh_malloc(sizeof(*buf));
      if (buf)
        /* This buffer will be deleted after use */
        buf->pre_allocated = 0;
    }

  return buf;
}


__inline void
ssh_iodevice_buffer_free(SshInterceptorIoDevice io_dev, 
                         SshDeviceBuffer buf)
{
  ssh_free(buf->addr);

  if (buf->pre_allocated == 1)
    NdisInterlockedInsertTailList(&io_dev->free_list, &buf->link, 
                                  &io_dev->free_list_lock);
  else
    ssh_free(buf);
}


/* Exported functions */

SshInterceptorIoDevice
ssh_interceptor_iodevice_alloc(SshInterceptor interceptor,
                               const unsigned char *device_name,
                               Boolean exclusive_access,
                               SshInterceptorIoDeviceStatusCB status_cb,
                               SshInterceptorIoDeviceReceiveCB receive_cb,
                               void *callback_context)
{
  SshInterceptorIoDevice io_dev = NULL;
  UINT i;

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("Allocating I/O device object '%s'", device_name));

  /* Create device object */
  io_dev = ssh_calloc(1, sizeof(*io_dev));
  if (io_dev == NULL) 
    {
      SSH_DEBUG(SSH_D_FAIL,("Memory allocation failed")); 
      return NULL;
    }

  io_dev->notify_event = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (io_dev->notify_event == NULL) 
    {
      SSH_DEBUG(SSH_D_FAIL,("Failed to create event object")); 
      ssh_free(io_dev);
      return NULL;
    }
		
  /* Initialize variables allocated in the device extension area */
  io_dev->open = 0;
  io_dev->cancel_io = 0;
  io_dev->status_cb = status_cb;
  io_dev->receive_cb = receive_cb;
  io_dev->cb_context = callback_context;

  NdisInitializeListHead(&io_dev->output_queue);
  NdisInitializeListHead(&io_dev->unreliable_output_queue);
  NdisAllocateSpinLock(&io_dev->output_queue_lock);
  NdisInitializeListHead(&io_dev->free_list);
  NdisAllocateSpinLock(&io_dev->free_list_lock);

  /* Initialize the read critical section. */
  InitializeCriticalSection(&io_dev->read_cs);

  /* Pre-allocate some "free" SshDeviceBuffers */
  for (i = 0; i < SSH_IODEVICE_QUEUE_SIZE; i++)
    {
      SshDeviceBuffer buf = &(io_dev->pre_allocated_buffers[i]);

      buf->pre_allocated = 1;
      InsertTailList(&io_dev->free_list, &buf->link);
    }

  SSH_ASSERT(interceptor->ipm_device == NULL);
  interceptor->ipm_device = io_dev;

  return io_dev;
}

Boolean __fastcall
ssh_interceptor_iodevice_create_device(SshInterceptorIoDevice io_dev)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Creating stream device..."));

  io_dev->handle = ActivateDeviceEx(TEXT("Drivers\\BuiltIn\\QuickSec"),
                                    NULL, 0, NULL);
  if (io_dev->handle == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                    SSH_LOG_CRITICAL,
                    ("Failed to register QSI1 device"));
      return FALSE;
    } 
	
  return TRUE;
}


void __fastcall
ssh_interceptor_iodevice_close_device(SshInterceptorIoDevice io_dev)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Closing stream device..."));

  SSH_ASSERT(io_dev != NULL);
  SSH_ASSERT(ssh_interceptor_iodevice_is_open(io_dev) == FALSE);

  if (io_dev->handle)  
    DeactivateDevice(io_dev->handle);
}


void 
ssh_interceptor_iodevice_free(SshInterceptorIoDevice io_dev)
{
  if (io_dev == NULL)
    return;

  SSH_ASSERT(ssh_interceptor_iodevice_is_open(io_dev) == FALSE);

  NdisFreeSpinLock(&io_dev->output_queue_lock);
  NdisFreeSpinLock(&io_dev->free_list_lock);

  if (io_dev->notify_event)
    CloseHandle(io_dev->notify_event);

  /* Delete the read critical section. */
  DeleteCriticalSection(&io_dev->read_cs);

  ssh_free(io_dev);

  SSH_DEBUG(SSH_D_HIGHOK, ("I/O device object 0x%p freed.", io_dev));
}



/*

*/
Boolean
ssh_interceptor_iodevice_send(SshInterceptorIoDevice io_dev,
                              unsigned len,
                              unsigned char *addr,
                              Boolean reliable)
{
  SshDeviceBuffer buf = NULL;
  Boolean st = FALSE;


  SSH_ASSERT(addr != NULL); /* Check that we have a valid packet */
  SSH_ASSERT(len > 0);
  SSH_ASSERT(len <= 0x7FFFFFFF); /* Our length field is "only" 31 bits long */

  /* No need to use spin lock (yet), because nothing bad happens if the I/O 
     device will be closed between this check and the moment when we acquire 
     an output queue spin lock. */
  if (io_dev->open)
    buf = ssh_iodevice_buffer_alloc(io_dev, reliable);

  if (buf)
    {
      buf->len = len;
      buf->addr = addr;
      buf->offset = 0;
      if (reliable)
        buf->reliable = 1;
      else
        buf->reliable = 0;

      NdisAcquireSpinLock(&io_dev->output_queue_lock);
      /* This time it's important that we read correct value from
         'io_dev->open', so we must protect also this check with a
         spin lock */
      if (io_dev->open)
        {
          InsertTailList(&io_dev->output_queue, &buf->link);

          if (reliable == FALSE)
            InsertTailList(&io_dev->unreliable_output_queue,
                           &buf->unreliable_list_link);

          st = TRUE;
        }
      NdisReleaseSpinLock(&io_dev->output_queue_lock);
    }

  if (st != TRUE)
    {
      ssh_free(addr);

      if (buf != NULL)
        {
          buf->addr = NULL;
          ssh_iodevice_buffer_free(io_dev, buf);
        }
    }
  else
    {
      SSH_ASSERT(io_dev->notify_event != NULL);

      SetEvent(io_dev->notify_event);
    }

  return st;
}


/************************ Stream Interface Functions ************************/

#pragma warning(push)
#pragma warning(disable : 4100)
__declspec(dllexport) DWORD WINAPI 
QSI_Init(LPCTSTR reg_path, 
         LPCVOID bus_context) 
{
  return ((DWORD)the_interceptor);
}
#pragma warning(pop)


__declspec(dllexport) BOOL WINAPI 
QSI_Deinit(DWORD device_context) 
{
  SshInterceptor interceptor = (SshInterceptor)device_context;
  HANDLE qs_handle;

  /* Validate the device context. */
  if (interceptor != the_interceptor)
    return FALSE;

  /* Perform unload processing. */
  DriverUnload(interceptor->driver_object);

  /* Decrement this modules reference count. */
  qs_handle = GetModuleHandle(FNAME_QUICKSEC);
  if (qs_handle) 
    FreeLibrary(qs_handle);
	
  return TRUE;
}


__declspec(dllexport) DWORD WINAPI 
QSI_Open(DWORD device_context, 
         DWORD access_code, 
         DWORD share_mode) 
{
  SshInterceptor interceptor = (SshInterceptor)device_context;
  SshInterceptorIoDevice io_dev;

  /* Validate the device context. */
  if (interceptor != the_interceptor)
    return 0;

  io_dev = the_interceptor->ipm_device;

  /* Validate the stream device */
  if (io_dev == NULL)
    return 0;
  
  /* Validate the reference count for exclusive access. */
  if (InterlockedIncrement(&io_dev->stream_interface_refcount) > 1) 
    {
      InterlockedDecrement(&io_dev->stream_interface_refcount);
      return 0;
    }

  /* Initialize packetizer object */
  ssh_interceptor_pktizer_init(&io_dev->pktizer, 
                               io_dev->receive_cb, 
                               io_dev->cb_context);

  /* Indicate that the device is open. */
  io_dev->open = 1;

  /* Indicate the open status as appropriate. */
  if (io_dev->status_cb) 
    io_dev->status_cb(TRUE, io_dev->cb_context);

  return ((DWORD)io_dev);
}


__declspec(dllexport) BOOL WINAPI 
QSI_Close(DWORD open_context) 
{
  SshInterceptorIoDevice io_dev = (SshInterceptorIoDevice)open_context;

  /* Validate the context. */
  if (io_dev != the_interceptor->ipm_device)
    return FALSE;
		
  /* Decrement the reference count as appropriate. */
  if (InterlockedDecrement(&io_dev->stream_interface_refcount) == 0) 
    {
      /* Indicate that the device is now closed. */
      NdisAcquireSpinLock(&io_dev->output_queue_lock);
      io_dev->open = 0;
      io_dev->cancel_io = 0;
      NdisReleaseSpinLock(&io_dev->output_queue_lock);

      /* Uninitialize the packetizer object */
      ssh_interceptor_pktizer_uninit(&io_dev->pktizer);

      /* Indicate the close status. */
      if (io_dev->status_cb) 
        io_dev->status_cb(FALSE, io_dev->cb_context);
	
      /* Free any buffers in the output queue. */
      while (!IsListEmpty(&io_dev->output_queue)) 
        {
          SshDeviceBuffer buf;
          PLIST_ENTRY entry;

          entry = RemoveHeadList(&io_dev->output_queue);
          buf = CONTAINING_RECORD(entry, SshDeviceBufferStruct, link);
          ssh_iodevice_buffer_free(io_dev, buf);
        };

      if (io_dev->current_read_buf)
        {
          ssh_iodevice_buffer_free(io_dev, io_dev->current_read_buf);
          io_dev->current_read_buf = NULL;
        }
    }
  else
    {
      SSH_NOTREACHED;
    }

  return TRUE;
}


__declspec(dllexport) DWORD WINAPI 
QSI_Read(DWORD open_context, 
         LPVOID output_buffer, 
         DWORD output_buffer_size) 
{
  SshInterceptorIoDevice io_dev = (SshInterceptorIoDevice)open_context;
  SshDeviceBuffer buffer;
  unsigned char *dest = output_buffer;
  DWORD dest_size = output_buffer_size;
  DWORD total_bytes_copied = 0;
  DWORD bytes_copied;

  if (io_dev != the_interceptor->ipm_device)
    return 0;

  /* Validate the buffer pointer. */
  if (output_buffer == NULL)
    return 0;

  /* Enter the read critical section. */
  EnterCriticalSection(&io_dev->read_cs);

 wait:

  /* Check for a closed interface. */
  if (!io_dev->open) 
    {
      LeaveCriticalSection(&io_dev->read_cs);
      return 0;
    }

  /* Wait for data. */
  if (WaitForSingleObject(io_dev->notify_event, INFINITE) != WAIT_OBJECT_0)
    {
      LeaveCriticalSection(&io_dev->read_cs);
      return 0;
    }

  /* CancelIo request? */
  if (io_dev->cancel_io)
    {
      LeaveCriticalSection(&io_dev->read_cs);
      return 0;
    }

  /* Re-check for a closed interface. */
  if (!io_dev->open) 
    {
      LeaveCriticalSection(&io_dev->read_cs);
      return 0;
    }

  buffer = io_dev->current_read_buf;

  do
    {
      bytes_copied = 0;

      /* Perform queue retrieval as appropriate. */
      if (buffer == NULL) 
        {
          PLIST_ENTRY entry;

          NdisAcquireSpinLock(&io_dev->output_queue_lock);

          /* Remove an entry from the queue as appropriate. */
          if (!IsListEmpty(&io_dev->output_queue)) 
            {
              entry = RemoveHeadList(&io_dev->output_queue);

              buffer = CONTAINING_RECORD(entry, SshDeviceBufferStruct, link);

              /* Remove the buffer also from the unreliable output queue 
                 as appropriate. */
              if (!buffer->reliable) 
                RemoveEntryList (&buffer->unreliable_list_link);
            }

          NdisReleaseSpinLock (&io_dev->output_queue_lock);
        }

      if (buffer == NULL) 
        {
          if (total_bytes_copied == 0)
            goto wait;
          break;
        }

      /* Determine the number of bytes to read. */
      bytes_copied = buffer->len;

      /* Adjust the number of bytes read as appropriate. */
      if (bytes_copied > dest_size) 
        bytes_copied = dest_size;

      /* Transfer the data from the buffer. */
      memcpy(dest, (buffer->addr + buffer->offset), bytes_copied);
      dest += bytes_copied;
      dest_size -= bytes_copied;

      /* Update the buffer read offset. */
      buffer->offset += bytes_copied;
      buffer->len -= bytes_copied;

      if (buffer->len == 0) 
        {
          /* Free the buffer. */
          ssh_iodevice_buffer_free(io_dev, buffer); 
          buffer = NULL;
        }

      total_bytes_copied += bytes_copied;
    }
  while ((bytes_copied > 0) && (dest_size > 0));

  io_dev->current_read_buf = buffer;

  LeaveCriticalSection(&io_dev->read_cs);

  return total_bytes_copied;
}


__declspec(dllexport) DWORD WINAPI 
QSI_Write(DWORD open_context, 
          LPVOID buffer, 
          DWORD length) 
{
  SshInterceptorIoDevice io_dev = (SshInterceptorIoDevice)open_context;

  /* Validate the open context. */
  if (open_context != (DWORD)io_dev) 
    return 0;

  /* We can't expect that write operation always succeeds. We could run out
  of memory in 'packetizer' and later we'll be in a deep trouble if we 
  always tell that we successfully delivered the data... */
  if (!ssh_interceptor_pktizer_receive(length, buffer, &io_dev->pktizer)) 
    return 0;

  return length;
}


__declspec(dllexport) BOOL WINAPI 
QSI_IOControl(DWORD open_context, 
              DWORD ioctl_code, 
              PBYTE input_buffer, 
              DWORD input_buffer_len, 
              PBYTE output_buffer, 
              DWORD output_buffer_len, 
              PDWORD bytes_returned) 
{
  SshInterceptorIoDevice io_dev = (SshInterceptorIoDevice)open_context;

  /* Validate the open context */
  if (open_context != (DWORD)io_dev)
    return FALSE;

  switch (ioctl_code)
    {
    case SSH_IOCTL_CANCEL_IO:
      io_dev->cancel_io = 1;
      SetEvent(io_dev->notify_event);
      *bytes_returned = 0;
      return TRUE;
    }

  /* I/O Control operations are not supported. */
  return FALSE;
}


__declspec(dllexport) DWORD WINAPI 
QSI_Seek(DWORD open_context, 
         long amount, 
         WORD type) 
{
  /* Seeks are not supported. */
  return SSH_INVALID_SEEK;
}


__declspec(dllexport) void WINAPI 
QSI_PowerUp(DWORD device_context) 
{
  /* Nothing to do */
}


__declspec(dllexport) void WINAPI 
QSI_PowerDown(DWORD device_context) 
{
  /* Nothing to do */
}

#endif /* _WIN32_WCE */
