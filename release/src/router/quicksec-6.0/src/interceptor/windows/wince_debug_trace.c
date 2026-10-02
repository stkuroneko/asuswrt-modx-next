/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Platform dependent support for writing a debug trace into persistent
   storage for Windows CE.
*/

#ifdef _WIN32_WCE

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"

#ifdef DEBUG_LIGHT

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_DEBUG_TRACE_GENERATIONS            4
#define SSH_DEBUG_TRACE_ENTRIES             1024
#define SSH_DEBUG_TRACE_SUBKEY_CHARS          64
#define SSH_DEBUG_TRACE_VALUENAME_CHARS       16
#define SSH_DEBUG_TRACE_VALUEDATA_CHARS     1024
#define SSH_DEBUG_TRACE_STRING_CHARS        1024

/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

static wchar_t ssh_debug_trace_subkey[SSH_DEBUG_TRACE_SUBKEY_CHARS];
static unsigned ssh_debug_trace_entry;
static Boolean ssh_debug_trace_enabled = FALSE;

static CRITICAL_SECTION ssh_debug_trace_critsect;

static wchar_t tmp_subkey[SSH_DEBUG_TRACE_SUBKEY_CHARS];
static wchar_t tmp_string[SSH_DEBUG_TRACE_STRING_CHARS];
static char tmp_string_asc[SSH_DEBUG_TRACE_STRING_CHARS];
static wchar_t tmp_valuename[SSH_DEBUG_TRACE_VALUENAME_CHARS];
static wchar_t tmp_valuedata[SSH_DEBUG_TRACE_VALUEDATA_CHARS];

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  ssh_debug_trace_init()
  
  Initialize storing diagnostic messages in the registry.
  
  Arguments:
  reg_path - 2nd argument to DriverEntry(), i.e. registry path to driver
             config under HKLM, as a UNICODE string.
  
  Returns:
  ------------------------------------------------------------------------*/
void
ssh_debug_trace_init(PUNICODE_STRING reg_path)
{
  LONG error;
  HKEY key;
  DWORD type, size, enable, generation;
  char *debug_string = tmp_string_asc;

  /* Open the config subkey. */

  _snwprintf(tmp_subkey, SSH_DEBUG_TRACE_SUBKEY_CHARS, L"%.*s",
             reg_path->Length, (wchar_t *)reg_path->Buffer);
  tmp_subkey[SSH_DEBUG_TRACE_SUBKEY_CHARS - 1] = L'\0';

  error = RegOpenKeyEx(HKEY_LOCAL_MACHINE, tmp_subkey, 0, 0, &key);
  if (error != ERROR_SUCCESS)
    return;

  /* Read the value that enables registry tracing. Stop here if it
     does not exist or is zero. */
  size = sizeof enable;
  error = RegQueryValueEx(key, L"TraceEnable", NULL, &type,
                          (BYTE *)&enable, &size);
  if (error != ERROR_SUCCESS || type != REG_DWORD || enable == 0)
    {
      RegCloseKey(key);
      return;
    }

  /* Read debug level string. Use "0" if it does not exist or is
     zero. */
  size = SSH_DEBUG_TRACE_STRING_CHARS * sizeof tmp_string[0];
  error = RegQueryValueEx(key, L"TraceString", NULL, &type,
                          (BYTE *)tmp_string, &size);
  if (error == ERROR_SUCCESS && type == REG_SZ && size > sizeof tmp_string[0])
    {
      tmp_string[size - 1] = L'\0';
      _snprintf(debug_string, SSH_DEBUG_TRACE_STRING_CHARS, "%ls", tmp_string);
      debug_string[SSH_DEBUG_TRACE_STRING_CHARS - 1] = '\0';
    }
  else
    {
      _snprintf(debug_string, SSH_DEBUG_TRACE_STRING_CHARS, "0");
    }

  /* Read the generation of the last trace and increment/wraparound
     it. Create it if it does not exist (ignoring error). */
  size = sizeof generation;
  error = RegQueryValueEx(key, L"TraceGeneration", NULL, &type,
                          (BYTE *)&generation, &size);

  if (error == ERROR_SUCCESS && type == REG_DWORD)
    {
      generation++;
      if (generation >= SSH_DEBUG_TRACE_GENERATIONS)
        generation = 0;
    }
  else
    {
      generation = 0;
    }

  if (error == ERROR_SUCCESS || error == ERROR_FILE_NOT_FOUND)
    RegSetValueEx(key, L"TraceGeneration", 0, REG_DWORD,
                  (BYTE *)&generation, sizeof generation);

  /* Close key. */
  RegCloseKey(key);

  /* Create/recreate the trace subkey. */
  _snwprintf(ssh_debug_trace_subkey, SSH_DEBUG_TRACE_SUBKEY_CHARS,
             L"%.*s\\Trace\\%02x",
             reg_path->Length, (wchar_t *)reg_path->Buffer,
             (unsigned)generation);
  ssh_debug_trace_subkey[SSH_DEBUG_TRACE_SUBKEY_CHARS - 1] = L'\0';

  /* Create/recreate the trace subkey of the current trace
     generation. Do not enable tracing if this fails. */
  error = RegDeleteKey(HKEY_LOCAL_MACHINE,
                       ssh_debug_trace_subkey);
  if (error == ERROR_SUCCESS || error == ERROR_FILE_NOT_FOUND)
    {
      error = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                             ssh_debug_trace_subkey,
                             0, NULL, 0, 0, NULL, &key, NULL);
      if (error == ERROR_SUCCESS)
        RegCloseKey(key);
    }
  if (error != ERROR_SUCCESS)
    return;

  /* Set the initial debug string and turn on tracing. */
  ssh_debug_set_level_string(debug_string);
  InitializeCriticalSection(&ssh_debug_trace_critsect);
  ssh_debug_trace_entry = 0;
  ssh_debug_trace_enabled = TRUE;
}

/*-------------------------------------------------------------------------
  ssh_debug_trace_uninit()
  
  Finish storing diagnostic messages in the registry.
  
  Arguments:
  
  Returns:
  ------------------------------------------------------------------------*/
void
ssh_debug_trace_uninit(void)
{
  ssh_debug_trace_enabled = FALSE;
  DeleteCriticalSection(&ssh_debug_trace_critsect);
}

/*-------------------------------------------------------------------------
  ssh_debug_trace()
  
  Routine for storing diagnostic messages in the registry.
  
  Arguments:
  msg - warning message string
  
  Returns:
  
  Notes:
  This function cannot call SSH_DEBUG functions. Also, other toolkit
  functions should be avoided as much as possible in order to keep this
  function immune to faults elsewhere in the toolkit.
  ------------------------------------------------------------------------*/
void
ssh_debug_trace(const char *msg)
{
  LONG error;
  HKEY key;
  DWORD valuedata_size;

  if (!ssh_debug_trace_enabled || !msg)
    return;

  /* Get exclusive access. */
  EnterCriticalSection(&ssh_debug_trace_critsect);

  /* Open the trace subkey. */
  error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                       ssh_debug_trace_subkey,
                       0, 0, &key);
  if (error != ERROR_SUCCESS)
    goto end;

  /* Write the message in the current entry. Ignore error. */
  _snwprintf(tmp_valuename, SSH_DEBUG_TRACE_VALUENAME_CHARS, L"%04x",
             (unsigned)ssh_debug_trace_entry);
  tmp_valuename[SSH_DEBUG_TRACE_VALUENAME_CHARS - 1] = L'\0';

  _snwprintf(tmp_valuedata, SSH_DEBUG_TRACE_VALUEDATA_CHARS, L"%08x: %hs",
             (unsigned)GetTickCount(), msg);
  tmp_valuedata[SSH_DEBUG_TRACE_VALUEDATA_CHARS - 1] = L'\0';
  valuedata_size = (wcslen(tmp_valuedata) + 1) * sizeof tmp_valuedata[0];

  RegSetValueEx(key, tmp_valuename, 0, REG_SZ,
                (BYTE *)tmp_valuedata, valuedata_size);

  /* Close key. */
  RegCloseKey(key);

  /* Advance/wraparound current value index. */
  ssh_debug_trace_entry++;
  if (ssh_debug_trace_entry >= SSH_DEBUG_TRACE_ENTRIES)
    ssh_debug_trace_entry = 0;

  /* End exclusive access. */
 end:
  LeaveCriticalSection(&ssh_debug_trace_critsect);
}

/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

#endif /* DEBUG_LIGHT */

#endif /* _WIN32_WCE */
