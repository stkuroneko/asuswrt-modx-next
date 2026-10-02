/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Platform dependent file I/O helper functions for Windows CE and Windows
   Mobile operating systems.
*/

#ifdef _WIN32_WCE

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "file_io.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

HANDLE
ssh_file_create(unsigned char *filename,
                Boolean allow_read)
{
  UNICODE_STRING uc_name;
  ANSI_STRING ansi_name;
  HANDLE handle = NULL;
  ULONG share_access = 0;

  if (allow_read)
    share_access |= FILE_SHARE_READ;

  RtlInitAnsiString(&ansi_name, filename);

  uc_name.Length = 0;
  uc_name.MaximumLength = (ansi_name.Length + 1) * sizeof(WCHAR);
  uc_name.Buffer = ssh_calloc(1, uc_name.MaximumLength);
  if (uc_name.Buffer == NULL)
    return NULL;

  if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uc_name, &ansi_name, FALSE)))
    {
      handle = CreateFile(uc_name.Buffer, GENERIC_WRITE, 
                          share_access, NULL, CREATE_ALWAYS, 
                          FILE_ATTRIBUTE_NORMAL, NULL);

      if (handle == INVALID_HANDLE_VALUE)
        handle = NULL;
    }
 
  ssh_free(uc_name.Buffer);

  return handle;
}


Boolean
ssh_file_write(HANDLE file,
               void *data,
               SshUInt32 data_len)
{
  SshUInt32 bytes_written = 0;

  if (WriteFile(file, data, data_len, &bytes_written, NULL)
      && (bytes_written == data_len))
    return TRUE;
  else
    return FALSE;
}


void
ssh_file_close(HANDLE file)
{
  CloseHandle(file);
}

#endif /* _WIN32_WCE */
