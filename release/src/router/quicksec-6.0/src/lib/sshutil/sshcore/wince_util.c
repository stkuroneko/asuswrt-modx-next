/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Windows CE specific implementations of required functions not natively
   supported in WinCE.
*/

#include "sshincludes.h"
#undef time
#undef localtime

#ifdef _WIN32_WCE

/* Windows CE doesn't have global variable errno. */
int errno = 0;

/* Windows CE doesn't have global variable timezone. */
long int timezone = 0;

/* Conversion union from FILETIME to unsigned __int64. (Microsoft's WinCE
   cross compilers can't do this conversion directly) */
typedef union
{
  unsigned __int64 u64;
  FILETIME ft;
} SshFileTime;

/* Number of 100 nanosecond units from 1/1/1601 to 1/1/1970 */
#define EPOCH_BIAS  116444736000000000i64

/* Prototype of non-UNICODE entry point. */
int
main(int argc, char *argv[]);

time_t __cdecl
time(time_t *timeptr)
{
  SYSTEMTIME st;
  SshFileTime ft;
  time_t ret_time;

  GetSystemTime(&st);
  SystemTimeToFileTime(&st, &ft.ft);

  ret_time = (time_t)((ft.u64 - EPOCH_BIAS) / 10000000i64);

  if (timeptr)
    *timeptr = ret_time;  /* store time if requested */

  return ret_time;
}


struct tm * __cdecl
localtime(const time_t *clock)
{
  static struct tm tm_local;
  TIME_ZONE_INFORMATION tzi;
  SshFileTime ft_utc, ft_local;
  SYSTEMTIME st;

  ft_utc.u64 = *clock * 10000000i64 + EPOCH_BIAS;

  if (!FileTimeToLocalFileTime(&ft_utc.ft, &ft_local.ft) ||
      !FileTimeToSystemTime(&ft_local.ft, &st))
    return NULL;

  tm_local.tm_sec = st.wSecond;
  tm_local.tm_min = st.wMinute;
  tm_local.tm_hour = st.wHour;
  tm_local.tm_mday = st.wDay;
  tm_local.tm_mon = st.wMonth - 1;
  tm_local.tm_year = st.wYear - 1900;
  tm_local.tm_wday = st.wDayOfWeek;
  tm_local.tm_yday = 0; /* sorry */

  switch (GetTimeZoneInformation(&tzi))
    {
    case TIME_ZONE_ID_UNKNOWN:
    case TIME_ZONE_ID_STANDARD:
      tm_local.tm_isdst = 0;
      timezone = tzi.Bias * 60;
      break;
    case TIME_ZONE_ID_DAYLIGHT:
      timezone = tzi.Bias * 60;
      tm_local.tm_isdst = 1;
      break;
    default:
      timezone = 0;
      break;
    }

  return &tm_local;
}


char *
strerror(int errnum)
{
  return "";



}


int
remove(const char *path)
{
  WCHAR uc_path[MAX_PATH];

  ssh_ascii_to_unicode(uc_path, sizeof(uc_path), path);
  if (DeleteFile(uc_path))
    return 0;
  else
    return -1;
}


/* Default UNICODE entry point for Windows CE applications. */
int
wmain(int argc, wchar_t *uc_argv[], wchar_t *uc_envp[])
{
  char **argv = NULL;

  /* convert the arguments (currently in 16-bit UNICODE character set) to
     ascii and call the generic main() */
  if (argc)
    {
      argv = ssh_calloc(argc, sizeof(char *));
      if (argv)
        {
          int i;

          for (i = 0; i < argc; i++)
            {
              size_t arg_size = wcslen(uc_argv[i]) + 1;

              argv[i] = ssh_calloc(1, arg_size);
              if (argv[i] == NULL)
                break;

              ssh_unicode_to_ascii(argv[i], arg_size, uc_argv[i]);
            }

          argc = i;
        }
      else
        {
          argc = 0;
        }
    }

  return (main(argc, argv));
}

#endif /* _WIN32_WCE */
