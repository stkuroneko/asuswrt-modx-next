/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The Windows entry-point to the quicksecpm program.
*/

#include "sshincludes.h"
#include "quicksec_pm.h"
#include "quicksecpm_i.h"
#include "ssheloop.h"
#include "sshglobals.h"
#ifndef _WIN32_WCE
#include <direct.h>
#endif /* _WIN32_WCE */


/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshIpsecPmWindows"


#define SSH_PM_SERVICENAME              "QUICKSECPM"
#define SSH_PM_SERVICEDISPLAYNAME       "INSIDE Secure QuickSec Policy Manager"

#define SSH_PM_MAXARGS                  32
#define SSH_PM_REGISTRY_SUBKEY          "Software\\INSIDESecure\\QuickSec"
#define SSH_PM_REGISTRY_PMPID           "PolicyManagerPid"
#define SSH_PM_REGISTRY_OUTPUTFILE      "OutputFile"
#define SSH_PM_CONTROL_QUEUE_NAME       "QuickSecPMControl"

int do_indicate = TRUE;

/***************************** Static variables *****************************/

/* The name of the program. */
static char *program;

#ifndef _WIN32_WCE
/* The arguments of the program.  These variables are used to pass the
   arguments to the service main function. */
static int s_argc;
static char **s_argv;

/* Service information. */
static SERVICE_STATUS_HANDLE pm_handle = INVALID_HANDLE_VALUE;
static SERVICE_STATUS pm_status;
#endif /* _WIN32_WCE */

/* Handle to the control message queue. */
static HANDLE control_queue_handle;

/***************************** Static functions *****************************/

/*
 * Convert a generic-text character into ASCII.
 */
static char ssh_ipm_arg_ascii(TCHAR tc)
{
#ifndef UNICODE
  return tc;
#else
  if (_istascii(tc))
    return tc & 0xff;
  else
    return '_';
#endif
}

/*
 * Advance *src to point to the next non-space characters. Return TRUE
 * if any spaces were encountered, FALSE otherwise.
 */
static Boolean ssh_ipm_arg_space(TCHAR **src)
{
  if (!_istspace(**src))
    return FALSE;

  do
    (*src)++;
  while (_istspace(**src));
  return TRUE;
}

/*
 * Return TRUE if *src points to a null character.
 */
static Boolean ssh_ipm_arg_end(TCHAR **src)
{
  return **src == _T('\0') ? TRUE : FALSE;
}

/*
 * If *src points to a non-space, non-null character, parse a word
 * terminated by a space or null, possibly containing parts enclosed
 * in double quotes.  Spaces within a quoted part do not terminate the
 * word. Store characters of the word in **dst, incrementing *dst
 * after each character. If a word was parsed, terminate it with a
 * null character and return TRUE, otherwise return FALSE. Note that
 * if the word was just two double quotes, no characters except the
 * terminating null are stored.
 */
static Boolean ssh_ipm_arg_word(TCHAR **src, char **dst)
{
  if (_istspace(**src) || **src == _T('\0'))
    return FALSE;

  do
    {
      if (**src != _T('"'))
        *(*dst)++ = ssh_ipm_arg_ascii(*(*src)++);
      else
        {
          (*src)++;
          while (**src != _T('"') && **src != _T('\0'))
            *(*dst)++ = ssh_ipm_arg_ascii(*(*src)++);
          if (**src == _T('"'))
            (*src)++;
        }
    }
  while (!_istspace(**src) && **src != _T('\0'));

  *(*dst)++ = '\0';
  return TRUE;
}

/*
 * Split a TCHAR command line into ASCII argument array. Return TRUE
 * if successful.
 */
static Boolean ssh_ipm_split_args(TCHAR *args, char *argv0,
                                  char **argv[], int *argc)
{
  char **argtab = NULL, *argbuf = NULL, *dst;
  TCHAR *src = args;
  int argnum;

  argtab = ssh_malloc(SSH_PM_MAXARGS * sizeof argtab[0]);
  argbuf = ssh_malloc(_tcslen(args));
  if (argtab == NULL || argbuf == NULL)
    goto fail;

  dst = argbuf;
  argnum = 0;

  argtab[argnum++] = argv0;

  ssh_ipm_arg_space(&src);

  while (!ssh_ipm_arg_end(&src))
    {
      if (argnum >= SSH_PM_MAXARGS)
        goto fail;

      argtab[argnum++] = dst;

      if (!ssh_ipm_arg_word(&src, &dst))
        goto fail;

      ssh_ipm_arg_space(&src);
    }

  *argv = argtab;
  *argc = argnum;
  return TRUE;

 fail:
  if (argbuf)
    ssh_free(argbuf);
  if (argtab)
    ssh_free(argtab);
  return FALSE;
}

/* Signal handler for stopping the policy manager. */
static void
ssh_ipm_quit_handler(int sig, void *context)
{
  static unsigned int num_calls = 0;

  num_calls++;

  if (num_calls > 1)
    {
      if (num_calls >= 5)
        {
          exit(1);
        }

      fprintf(stderr,
              "Policy manager is already stopping.  %s %u more time%s "
              "to exit immediately.\n",



              "Hit C-c",

              5 - num_calls,
              5 - num_calls > 1 ? "s" : "");
      return;
    }

  /* Stop the policy manager. */
  ssh_ipm_stop();
}

#ifndef _WIN32_WCE
/* Copies the error message of GetLastError to buf. Returns buf */
static LPTSTR
GetLastErrorText(LPTSTR buf, DWORD size)
{
  DWORD ret;
  LPTSTR str = NULL;

  /* Get the message string */
  ret = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_ARGUMENT_ARRAY,
                      NULL, GetLastError(), LANG_NEUTRAL,
                      (LPTSTR)&str, 0, NULL );


  if (!ret || ((long) size < (long) ret + 14))
    {
      /* Error or buffer too small */
      buf[0] = TEXT('\0');
    }
  else
    {
      /* Remove cr and newline character */
      str[lstrlen(str) - 2] = TEXT('\0');

      /* Copy the message and error code to buffer */
      ssh_snprintf(buf, size, TEXT("%s (0x%x)"), str, GetLastError() );
    }

  if (str)
    LocalFree((HLOCAL)str);

  return buf;
}

/***************** Installing and removing Windows service ******************/
static void
ssh_ipm_install_service(int argc, char *argv[])
{
  SC_HANDLE service;
  SC_HANDLE scm;
  unsigned char path[1024], errtxt[256];
  size_t len;
  int i;

  /* Get the executable file name */
  if (GetModuleFileName(NULL, path, sizeof(path)) == 0)
    {
      ssh_fatal("ssh_ipm_install_service: GetModuleFileName() failed: %s",
                GetLastErrorText(errtxt, sizeof(errtxt)));
      return;
    }

  /* Open SCM */
  scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (scm == NULL)
    ssh_fatal("ssh_ipm_install_service: OpenSCManager() failed: %s",
              GetLastErrorText(errtxt, sizeof(errtxt)));

  /* Append the command line switches. When the service is started, switches
     are passed to main(...), as normally. */
  len = ssh_ustrlen(path);
  for (i = 0; i < argc; i++)
    {
      if ((sizeof(path) - len) < (strlen(argv[i]) + 2))
        {
          CloseServiceHandle(scm);
          ssh_fatal("ssh_ipm_install_service: failed to copy arguments");
        }
      if (!strcmp(argv[i-1], "-f"))
        {
          unsigned char *ch = "\"";
          ssh_snprintf(&path[len], sizeof(path) - len, " %s%s%s",
                        ch, argv[i], ch);
          len += ssh_ustrlen(&path[len]);
        }
      else
        {
          ssh_snprintf(&path[len], sizeof(path) - len, " %s", argv[i]);
          len += ssh_ustrlen(&path[len]);
        }
    }

  service = CreateService(
        scm,                    /* SCM database */
        TEXT(SSH_PM_SERVICENAME),/* name of service */
        TEXT(SSH_PM_SERVICEDISPLAYNAME), /* name to display */
        SERVICE_ALL_ACCESS,     /* desired access */
        (SERVICE_WIN32_OWN_PROCESS /* service type */
         | SERVICE_INTERACTIVE_PROCESS),
        SERVICE_AUTO_START,     /* start type */
        SERVICE_ERROR_NORMAL,   /* error control type */
        path,                   /* service's binary */
        NULL,                   /* load ordering group */
        NULL,                   /* tag identifier */
        NULL,                   /* dependencies */
        NULL,
        NULL);

  if (service == NULL)
    {




      ssh_warning("%s", GetLastErrorText(errtxt, sizeof(errtxt)));

      CloseServiceHandle(scm);
      return;
    }

  ssh_warning("%s installed.", SSH_PM_SERVICEDISPLAYNAME);

  CloseServiceHandle(service);
  CloseServiceHandle(scm);
}


static void
ssh_ipm_remove_service(void)
{
  SC_HANDLE service;
  SC_HANDLE scm;
  SERVICE_STATUS status;
  char errtxt[256];

  scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (scm == NULL)
    ssh_fatal("ssh_ipm_remove_service: OpenSCManager() failed: %s",
              GetLastErrorText(errtxt, sizeof(errtxt)));

  service = OpenService(scm, SSH_PM_SERVICENAME, SERVICE_ALL_ACCESS);
  if (service == NULL)
    {




      ssh_warning("%s", GetLastErrorText(errtxt, sizeof(errtxt)));

      CloseServiceHandle(scm);
      return;
    }

  /* Try to stop the service */
  if (ControlService(service, SERVICE_CONTROL_STOP, &status))
    {
      ssh_warning("Stopping %s.", SSH_PM_SERVICEDISPLAYNAME);
      Sleep(1000);

      /* Wait until the service is stopped */
      while (QueryServiceStatus(service, &status))
        {
          if (status.dwCurrentState == SERVICE_STOP_PENDING)
            {
              SSH_TRACE(0, ("Waiting for service to stop."));
              Sleep(1000);
            }
          else
            break;
        }

      if (status.dwCurrentState == SERVICE_STOPPED)
        ssh_warning("%s stopped.", SSH_PM_SERVICEDISPLAYNAME);
      else
        ssh_warning("%s failed to stop.", SSH_PM_SERVICEDISPLAYNAME);
    }

  /* Delete the service */
  if (DeleteService(service))
    ssh_warning("%s removed.\n", SSH_PM_SERVICEDISPLAYNAME);
  else
    ssh_warning("DeleteService failed: %s\n",
                GetLastErrorText(errtxt, sizeof(errtxt)));

  CloseServiceHandle(service);
  CloseServiceHandle(scm);
}


/********************** Windows service functionality ***********************/

/* Report the status of the service. */
static void
report_service_status(unsigned int *status)
{
  if (status != &pm_status.dwCurrentState)
    {
      if (*status == SERVICE_START_PENDING)
        pm_status.dwControlsAccepted = 0;
      else
        pm_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

      pm_status.dwCurrentState = *status;
    }
  pm_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  pm_status.dwServiceSpecificExitCode = 0;
  pm_status.dwWin32ExitCode = 0;
  pm_status.dwCheckPoint++;
  pm_status.dwWaitHint = 5000;

  if (pm_handle == INVALID_HANDLE_VALUE)
    return;

  SetServiceStatus(pm_handle, &pm_status);
}

/* Service control routine. Handles control messages sent by
   ControlService.  Need to handle only SERVICE_CONTROL_STOP
   message. */
static void WINAPI
service_ctrl(DWORD code)
{
  switch (code)
    {
    case SERVICE_CONTROL_STOP:
      /* Don't call ssh_ipm_stop() directly, because doing so causes
         a potential race condition. (service_ctrl() is executed on a
         context of another thread) */
      raise(SIGINT);
      break;

    default:
      /* Report previous status to the SCM */
      report_service_status(&pm_status.dwCurrentState);
      break;
    }
}

/* The service main function.  This will fetch the original arguments
   of the program and pass them to the generic policy manager main.
   But, first this will do some service related initialization. */
static void WINAPI
service_main(DWORD argc, LPTSTR *argv)
{
  char *cp;

  /* Extract the working directory from the program name. */
  cp = strrchr(s_argv[0], '\\');
  if (cp)
    {
      char path[MAX_PATH];
      size_t len = cp - s_argv[0];

      SSH_ASSERT(len < MAX_PATH);

      /* This is an absolute path name.  Let's change our working
         directory to that. */
      memcpy(path, s_argv[0], len);
      path[len] = '\0';

      _chdir(path);
    }

  /* Init policy manager and SSH libraries. Do the initialization here
   so that ssh_event_loop_initialization() and ssh_event_loop_run() are
   called in the context of the same thread. */
  ssh_ipm_init();

  ssh_register_signal(SIGINT, ssh_ipm_quit_handler, NULL);

  /* Register the service control handler.  Has to be done first */
  pm_handle = RegisterServiceCtrlHandler(SSH_PM_SERVICENAME, service_ctrl);

  /* Call the generic main which will actually start the policy
     manager. */
  ssh_ipm_start(s_argc, s_argv);
}

/* Start the policy manager as a Windows service. */
static void
start_service(void)
{
  char errtxt[256];
  SERVICE_TABLE_ENTRY services[] =
  {
    {TEXT(SSH_PM_SERVICENAME), service_main},
    {NULL, NULL},
  };

  if (!StartServiceCtrlDispatcher(services))
    ssh_fatal("StartServiceCtrlDispatcher: %s",
              GetLastErrorText(errtxt, sizeof(errtxt)));
}
#endif /* _WIN32_WCE */

/******************************** Other utilities ****************************/

#ifdef _WIN32_WCE

/*
 * Read the specified string value from the policy manager
 * configuration registry subkey into a buffer, the size of which in
 * bytes is given by size. Make sure the string is
 * null-terminated. Return TRUE on success.
 */
static Boolean get_config_string(const TCHAR *value, void *buffer, DWORD size)
{
  HKEY key = NULL;
  DWORD type, value_size = size;
  Boolean status = FALSE;

  if (RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        _T(SSH_PM_REGISTRY_SUBKEY),
        0,
        0,
        &key) != ERROR_SUCCESS)
    goto end;

  if (RegQueryValueEx(
        key,
        value,
        NULL,
        &type,
        (LPBYTE)buffer,
        &value_size) != ERROR_SUCCESS)
    goto end;

  if (type != REG_SZ)
    goto end;

  if (value_size < sizeof(TCHAR))
    goto end;

  *(TCHAR *)((LPBYTE)buffer + value_size - sizeof(TCHAR)) = _T('\0');
  status = TRUE;

 end:
  if (key)
    RegCloseKey(key);

  return status;
}


/* Append another string into a null-terminated string in a buffer of
   the specified size. Return TRUE if successful, FALSE if there is
   not enough space in the buffer. */
static Boolean append_string(TCHAR *buffer, DWORD size, const TCHAR *string)
{
  DWORD l = _tcslen(buffer);

  if ((l + _tcslen(string)) * sizeof(buffer[0]) >= size)
    return FALSE;

  _tcscpy(buffer + l, string);
  return TRUE;
}


/* This function is declared in the OEM headers which we do not
   necessarily include. */
BOOL SetStdioPathW(DWORD id, LPCWSTR pwszPath);

/*
 * Redirect stdout and stderr into the specified file. Before that,
 * try deleting the file if possible but if not, just append to the
 * file. Register the output file in registry.
 */
static void set_output_file(char *file)
{
  HKEY key = NULL;
  TCHAR *output_file = NULL;
  TCHAR *moved_file;
  DWORD len = strlen(file);

  output_file = ssh_malloc((len + 1) * sizeof output_file[0]);
  if (output_file == NULL)
    return;

  _sntprintf(output_file, len + 1, _T("%hs"), file);

  if (!DeleteFile(output_file) && GetLastError() == ERROR_SHARING_VIOLATION)
    {
      moved_file = ssh_malloc((len + 1) * sizeof(TCHAR));
      if (moved_file != NULL)
        {
          _tcscpy(moved_file, output_file);
          moved_file[_tcslen(moved_file) - 1] = _T('_');

          DeleteFile(moved_file);
          MoveFile(output_file, moved_file);

          ssh_free(moved_file);
        }
    }

  /* Redirect stdout and stderr and set to unbuffered mode. */
  SetStdioPathW(1, output_file);
  SetStdioPathW(2, output_file);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        _T(SSH_PM_REGISTRY_SUBKEY),
        0,
        NULL,
        0,
        0,
        NULL,
        &key,
        NULL) != ERROR_SUCCESS)
    {
      ssh_warning("Cannot open/create registry subkey");
      goto end;
    }

  if (RegSetValueEx(
        key,
        _T(SSH_PM_REGISTRY_OUTPUTFILE),
        0,
        REG_SZ,
        (BYTE *)output_file,
        (len + 1) * sizeof output_file[0]) != ERROR_SUCCESS)
    {
      ssh_warning("Cannot store output file name in registry");
      goto end;
    }

end:
  if (key)
    RegCloseKey(key);
  if (output_file)
    ssh_free(output_file);
  return;
}

/*
 * Store the process id of the current process in registry.
 */
static Boolean register_process(void)
{
  HKEY key = NULL;
  DWORD type, pid, len;

  if (RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        _T(SSH_PM_REGISTRY_SUBKEY),
        0,
        NULL,
        0,
        0,
        NULL,
        &key,
        NULL) != ERROR_SUCCESS)
    {
      ssh_warning("Cannot open/create registry subkey");
      goto fail;
    }

  len = sizeof pid;

  if (RegQueryValueEx(
        key,
        _T(SSH_PM_REGISTRY_PMPID),
        NULL,
        &type,
        (BYTE *)&pid,
        &len) == ERROR_SUCCESS &&
      type == REG_DWORD &&
      len == sizeof pid &&
      OpenProcess(0, FALSE, pid))
    {
      ssh_warning("Process already running");
      goto fail;
    }

  pid = GetCurrentProcessId();

  if (RegSetValueEx(
        key,
        _T(SSH_PM_REGISTRY_PMPID),
        0,
        REG_DWORD,
        (BYTE *)&pid,
        sizeof pid) != ERROR_SUCCESS)
    {
      ssh_warning("Cannot store process id in registry");
      goto fail;
    }

  RegCloseKey(key);
  return TRUE;

fail:
  if (key)
    RegCloseKey(key);
  return FALSE;
}

static void control_callback(void *context);

/*
 * Create/open named message queue for reading control messages and
 * register handler for it.
 */
static void init_control_queue(void)
{
  MSGQUEUEOPTIONS mqo;

  memset(&mqo, 0, sizeof mqo);
  mqo.dwSize = sizeof mqo;
  mqo.dwFlags = MSGQUEUE_ALLOW_BROKEN;
  mqo.dwMaxMessages = 1;
  mqo.cbMaxMessage = 1024;
  mqo.bReadAccess = TRUE;

  if (!(control_queue_handle =
        CreateMsgQueue(_T(SSH_PM_CONTROL_QUEUE_NAME), &mqo)))
    {
      ssh_warning("Cannot initialize control message queue");
      return;
    }

  ssh_event_loop_register_handle(control_queue_handle, FALSE,
                                 control_callback, control_queue_handle);
}

/*
 * Uninit control message queue.
 */
static void uninit_control_queue(void)
{
  if (!control_queue_handle)
    return;

  ssh_event_loop_unregister_handle(control_queue_handle);
  CloseMsgQueue(control_queue_handle);
}

/*
 * Control message handler.
 */

SSH_GLOBAL_DECLARE(SshPm, ipm);
#define ipm SSH_GLOBAL_USE(ipm)

#define SSH_PM_CONTROL_STOP                   0
#define SSH_PM_CONTROL_RECONFIGURE            1
#define SSH_PM_CONTROL_REDO_FLOWS             2



#define SSH_PM_CONTROL_DEBUGSTRING_USERMODE   4
#define SSH_PM_CONTROL_DEBUGSTRING_KERNELMODE 5

typedef struct {
  DWORD type;
  union {
    char string[1000];
  } u;
} SshPmControlMessageStruct, *SshPmControlMessage;

static void control_callback(void *context)
{
  HANDLE h = (HANDLE)context;
  DWORD len, flags;
  BYTE buf[1024];
  SshPmControlMessageStruct msg;

  if (!ReadMsgQueue(h, buf, sizeof buf, &len, 0, &flags))
    {
      ssh_warning("ReadMsgQueue: error %u", GetLastError());
      return;
  }

  if (len > sizeof msg)
    {
      ssh_warning("Control message too large");
      return;
    }

  memcpy(&msg, buf, len);

  switch (msg.type)
    {
    case SSH_PM_CONTROL_STOP:
      ssh_ipm_stop();
      break;

    case SSH_PM_CONTROL_RECONFIGURE:
      ssh_ipm_reconfigure();
      break;

    case SSH_PM_CONTROL_REDO_FLOWS:
      ssh_ipm_redo_flows();
      break;







    case SSH_PM_CONTROL_DEBUGSTRING_USERMODE:
      ssh_debug_set_level_string(msg.u.string);
      break;

    case SSH_PM_CONTROL_DEBUGSTRING_KERNELMODE:
      if (ipm)
        ssh_pm_set_kernel_debug_level(ipm, msg.u.string);
      break;
    }
}

#endif /* _WIN32_WCE */

/******************* The main entry point to the program ********************/

#ifndef _WIN32_WCE

static int main_get_windows_major_version()
{
  OSVERSIONINFO os;
  int winver;

  memset(&os, 0, sizeof(os));

  os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

  GetVersionEx(&os);

  winver = os.dwMajorVersion;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Windows major version: %d",  winver));

  if (winver == 5 || winver == 6)
    return winver;
  else
    {
      printf("Unknown Windows major version: %d", winver);
      return 0;
    }
}

int
main(int argc, char *argv[])
{
  int ret_value;
  int i;
  int winver;

  winver = main_get_windows_major_version();
  if (winver != 5 && winver != 6)
    {
      printf("Invalid Windows version acquired (%d).", winver);
      return -1;
    }

#if (WINVER < _WIN32_WINNT_VISTA)
  if (winver != 5)
    {
      printf("Windows version not acceptable for"
             " this policymanager version (compiled for XP (major version=5), "
             "read OS major version=%d).", winver);
      return -1;
    }
#endif /* (WINVER < _WIN32_WINNT_VISTA) */

#if (WINVER >= _WIN32_WINNT_VISTA)
  if (winver != 6)
    {
      printf("Windows version not acceptable for this policymanager "
             "version (compiled for series VISTA/WINDOWS 7 (major version=6), "
             "read OS major version=%d).", winver);
      return -1;
    }
#endif /* (WINVER >= _WIN32_WINNT_VISTA) */

  /* Resolve the program name. */
  program = strrchr(argv[0], '\\');
  if (program)
    program++;
  else
    program = argv[0];

  /* Check arguments, phase 1.  We process the Windows-specific
     arguments here. */
  for (i = 1; i < argc; i++)
    {
      if (strcmp(argv[i], "--install-service") == 0)
        {
          char *new_arg = "-d";
          char *old_arg = argv[i];

          /* Install the policy manager as Windows service. */
          argv[i] = new_arg;
          ssh_ipm_install_service(argc - 1, &argv[1]);
          argv[i] = old_arg;
          return 0;
        }
      else if (strcmp(argv[i], "--remove-service") == 0)
        {
          /* Remote the policy manager Windows service. */
          ssh_ipm_remove_service();
          return 0;
        }
      else if (strcmp(argv[i], "-d") == 0)
        {
          /* Run as a daemon (or service in Windows terms). */
          s_argc = argc;
          s_argv = argv;

          /* Start the service. */
          start_service();
          return 0;
        }
    }

  /* Run as a normal command line application. */

  /* Init policy manager and SSH libraries. */
  ssh_ipm_init();

  ssh_register_signal(SIGINT, ssh_ipm_quit_handler, NULL);

  /* Call the generic program entry point. */
  ret_value = ssh_ipm_start(argc, argv);

  return ret_value;
}

#else /* _WIN32_WCE */

int
main(int argc, char *argv[])
{
  TCHAR args[1024], dstr[1024];
  int registry_args = 0;
  int ret_value;
  int i;

  /* Resolve the program name. */
  program = strrchr(argv[0], '\\');
  if (program)
    program++;
  else
    program = argv[0];
  argv[0] = program;

  /* If no arguments, try reading them from the registry. */

  if (argc == 1)
    {
      if (get_config_string(_T("Arguments"), args, sizeof args))
        {
          /* If there are saved debug strings in the registry, append
             corresponding command line arguments (overriding any
             debug strings in the original argument list). */
          if (get_config_string(_T("UserModeDebugString"), dstr, sizeof dstr)
              && dstr[0] != _T('\0'))
            {
              append_string(args, sizeof args, _T(" -D "));
              append_string(args, sizeof args, dstr);
            }
          if (get_config_string(_T("KernelModeDebugString"), dstr,sizeof dstr)
              && dstr[0] != _T('\0'))
            {
              append_string(args, sizeof args, _T(" -K "));
              append_string(args, sizeof args, dstr);
            }

          /* Convert the string into an argument list. */
          if (!ssh_ipm_split_args(args, argv[0], &argv, &argc))
            {
              fprintf(stderr, "Error reading arguments from registry.\n");
              return 1;
            }

          /* Cannot print anything on stdout/stderr yet, otherwise they
             cannot be redirected anymore. Set a flag to print a message
             later. */
          registry_args = 1;
        }
    }

  /* Win CE may not have a shell so `snoop' the -O option here and
     redirect stdout/stderr according to that. The option will be
     processed again in ssh_ipm_start() to redirect debug output. */
  for (i = 1; i < argc; i++)
      if ((!strcmp(argv[i], "-O") || !strcmp(argv[i], "--debug-output-file"))
          && i + 1 < argc)
        set_output_file(argv[i + 1]);

  if (registry_args)
    fprintf(stderr, "Using arguments from registry.\n");

  /* Init policy manager and SSH libraries. */
  ssh_ipm_init();

  /* Try registering the process id in the registry. */
  if (!register_process())
    return 1;

  /* Init process control facility. */
  init_control_queue();

  ssh_register_signal(SIGINT, ssh_ipm_quit_handler, NULL);

  /* Call the generic program entry point. */
  ret_value = ssh_ipm_start(argc, argv);

  return ret_value;
}

#endif /* _WIN32_WCE */

/********************* Callbacks from the generic code **********************/

Boolean
ssh_ipm_make_service(void)
{
  /* This is no-operation for Windows.  The daemon is created
     differently. */
  return TRUE;
}


void
ssh_ipm_report_state(SshIpmState state)
{
#ifndef _WIN32_WCE
  unsigned int s;

  switch (state)
    {
    case SSH_IPM_STARTING:
      s = SERVICE_START_PENDING;
      break;

    case SSH_IPM_RUNNING:
      s = SERVICE_RUNNING;
      break;

    case SSH_IPM_STOPPING:
      s = SERVICE_STOP_PENDING;
      break;

    case SSH_IPM_STOPPED:
      s = SERVICE_STOPPED;
      break;
    }

  report_service_status(&s);
#endif /* _WIN32_WCE */
}
