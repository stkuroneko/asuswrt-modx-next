/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Common definitions for Win32 and Win64 platforms.
*/

#ifndef SSHINCLUDES_WIN32
#define SSHINCLUDES_WIN32

#if !defined(WIN32) || defined(KERNEL)
#error "sshincludes_win32.h is for Win32 user mode builds only"
#endif
#include "sshwinconf.h"
#include "sshparams.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _WIN32_WCE
#pragma comment(lib, "ws2")
#else /* _WIN32_WCE */
#pragma comment(lib, "ws2_32")
#endif /* _WIN32_WCE */

/* Function calls across DLL boundary */
#ifdef DLL
#define DLLEXPORT __declspec(dllexport)
#else /* DLL */
#define DLLEXPORT
#endif /* DLL */

#define DLLCALLCONV

typedef unsigned char SshUInt8;         /* At least 8 bits. */
typedef signed char SshInt8;            /* At least 8 bits. */

typedef unsigned short SshUInt16;       /* At least 16 bits. */
typedef short SshInt16;                 /* At least 16 bits. */

typedef unsigned int SshUInt32;         /* At least 32 bits. */
typedef int SshInt32;                   /* At least 32 bits. */

typedef unsigned __int64 SshUInt64;
typedef __int64 SshInt64;

#define SIZEOF_SHORT        2
#define SIZEOF_INT          4
#define SIZEOF_LONG         4
#define SIZEOF_LONG_LONG    8

#if defined(_WIN64)
#define SIZEOF_VOID_P       8
#define SIZEOF_SIZE_T       8
#else
#define SIZEOF_VOID_P       4
#define SIZEOF_SIZE_T       4
#endif /* _WIN64 */

#define USERMODE_SIZEOF_VOID_P    (SIZEOF_VOID_P)
#define USERMODE_SIZEOF_SIZE_T    (SIZEOF_SIZE_T)

#define SSHUINT64_IS_64BITS
#define SSH_C64(x) ((SshUInt64)x)
#define SSH_S64(x) ((SshInt64)x)

#define HAVE_SHORT
#define HAVE_INT
#define HAVE_LONG
#define HAVE_LONG_LONG

/* use mb functions directly */
#define _MB_MAP_DIRECT

/* Disable deprecation */
#define _CRT_SECURE_NO_DEPRECATE

#include <windows.h>
#ifndef _WIN32_WCE
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif /* _WIN32_WCE */
#include <stdio.h>
#include <tchar.h>
#include <time.h>
#ifndef _WIN32_WCE
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <signal.h>
#else
#include <winsock2.h>
#include <winbase.h>
#include <wincrypt.h>
#include <winioctl.h>

#ifndef __cplusplus

#undef try
#undef except
#undef finally
#undef leave

#endif /* __cplusplus */

#define NO_ERRNO_H

#define ERANGE  34
#define EAGAIN  0
#define EINTR   0
#define _IONBF  0x0004

#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGEMT 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGBUS 10
#define SIGSEGV 11
#define SIGSYS 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGURG 16
#define SIGSTOP 17
#define SIGTSTP 18
#define SIGCONT 19
#define SIGCHLD 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGIO 23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGINFO 29
#define SIGUSR1 30
#define SIGUSR2 31

/* IOCTL code for I/O request cancellation. */
#define SSH_IOCTL_CANCEL_IO   \
  CTL_CODE(0x8000, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /* _WIN32_WCE */

#ifdef UNICODE

/* ANSI/ASCII to UNICODE (16-bit wide characters) conversion macro. */
#define ssh_ascii_to_unicode(uc_buff, buff_size, ascii_str)           \
do                                                                    \
{                                                                     \
  MultiByteToWideChar(CP_ACP, 0, (ascii_str), -1, (uc_buff),          \
                      (buff_size) / sizeof(WCHAR));                   \
}                                                                     \
while (0);

/* UNICODE (16-bit wide characters) to ANSI/ASCII conversion macro. */
#define ssh_unicode_to_ascii(ascii_buff, buff_size, unicode_str)      \
do                                                                    \
{                                                                     \
  WideCharToMultiByte(CP_ACP, 0, (unicode_str), -1, (ascii_buff),     \
                      (buff_size), NULL, NULL);                       \
}                                                                     \
while (0);

#endif /* UNICODE */

/* Data type for sockets on windows platform.
   Unlike unix, windows file operations are implemented using the
   event registration interface. The I/O interface is used for sockets only. */
typedef SOCKET SshIOHandle;

/*
  Aliases for some misc routines which do exist on Windows,
  but under different name.
*/

/* Aliases for some string-related routines */
#define HAVE_STRCASECMP
#define HAVE_STRNCASECMP

#define strcasecmp    _stricmp
#define strncasecmp   _strnicmp
#define popen         _popen
#define pclose        _pclose

#define rmdir         _rmdir

/* There is no lstat on Windows; just use stat. */
#define lstat         stat

/* Aliases for deprecated POSIX functions. */
#define fileno        _fileno
#ifndef _WIN32_WCE
#define open          _open
#define close         _close
#define read          _read
#define write         _write
#else

#define _getpid       GetCurrentProcessId
#define abort()       exit(1)
#define system(s)     0
#endif /* _WIN32_WCE */

#define off_t SshUInt64

/* Standard features provided by Win32 programming interface */

#define MAX max
#define MIN min

/* Missing pipe function declaration */
#define pipe(phandles) _pipe(phandles, 4096, _O_BINARY)


/* these defines are from Unix sys/mode.h */
#define S_ISUID         0004000         /* set user id on execution */
#define S_ISGID         0002000         /* set group id on execution */

                                        /* ->>> /usr/group definitions <<<- */
#define S_IRWXU         0000700         /* read,write,execute perm: owner */
#define S_IRUSR         0000400         /* read permission: owner */
#define S_IWUSR         0000200         /* write permission: owner */
#define S_IXUSR         0000100         /* execute/search permission: owner */
#define S_IRWXG         0000070         /* read,write,execute perm: group */
#define S_IRGRP         0000040         /* read permission: group */
#define S_IWGRP         0000020         /* write permission: group */
#define S_IXGRP         0000010         /* execute/search permission: group */
#define S_IRWXO         0000007         /* read,write,execute perm: other */
#define S_IROTH         0000004         /* read permission: other */
#define S_IWOTH         0000002         /* write permission: other */
#define S_IXOTH         0000001         /* execute/search permission: other */

#define STDIN_FILENO    0
#define STDOUT_FILENO   1

#if 0
#define S_IRUSR  _S_IREAD        /* read permission: owner */
#define S_IWUSR  _S_IWRITE       /* write permission: owner */
#define S_IXUSR  _S_IEXEC        /* execute permission: owner */
#endif

#define S_IFREG  _S_IFREG        /* regular */
#define S_IFDIR  _S_IFDIR        /* directory */
#define S_IFCHR  _S_IFCHR        /* character special */
#define S_IFLNK  0
#define S_IFBLK  0
#define S_IFIFO  0

#define S_IFMT _S_IFMT

#define S_ISDIR(m)      (((m)&(S_IFMT)) == (S_IFDIR))
#define S_ISCHR(m)      (((m)&(S_IFMT)) == (S_IFCHR))
#define S_ISREG(m)      (((m)&(S_IFMT)) == (S_IFREG))

/* Generic SSH utility routines implemented as macros */
#define ssh_sleep(secs, usecs)    Sleep(1000 * (secs) + (usecs) / 1000)

/* Needed by sshsessionincludes.h. */
typedef long pid_t;
typedef long uid_t;
typedef long gid_t;
typedef long mode_t;

/* some Unixes define MAXPATHLEN */
#define MAXPATHLEN  MAX_PATH

/* There is thread support in Windows. */
#define HAVE_THREADS

/* There is PCSC support in Windows. */
#define HAVE_PCSC

#ifndef _WIN32_WCE
/* There is getenv too! */
#define HAVE_GETENV
#endif /* _WIN32_WCE */

#define HAVE_LSTAT
#define HAVE_UTIME

/* windows has localtime(). */
#define HAVE_LOCALTIME
/* Windows has global variable 'timezone'.*/
#define HAVE_EXTERNAL_TIMEZONE
/* 'struct tm' has member 'tm_isdst'. */
#define HAVE_TM_ISDST_IN_STRUCT_TM













#ifndef inline
#define inline __inline
#endif /* inline */

/* Enable IPv6 support by default */
#define WITH_IPV6

#ifdef _WIN32_WCE
#define SSHMATH_MINIMAL 1

/* Declare replacement for missing timezone variable. */
extern long int timezone;

extern int errno;

char *strerror(int errnum);
int remove(const char *path);

#define getenv(e)  NULL
#endif /* _WIN32_WCE */


#ifdef SSHDIST_MSCAPI
/* If building with MSCAPI support indicate that we have alternative
   versions of AES, DES and 3DES algorithms. */
#ifdef WITH_MSCAPI
#define HAVE_MSCAPI_CRYPTO
#define HAVE_AES
#define HAVE_DES
#define HAVE_3DES
#define HAVE_SHA
#define HAVE_MD5

/* undefine certificate functionality provided by MSCAPI */
#undef SSHDIST_APPS_CERTUTILS
#undef SSHDIST_APPS_CERTUTILS_CERTVIEW
#undef SSHDIST_APPS_CERTUTILS_BERDUMP
#undef SSHDIST_APPS_CERTUTILS_CERTMAKE
#undef SSHDIST_APPS_CERTUTILS_KEYTOOL
#undef SSHDIST_APPS_CERTUTILS_P12EXTRACT
#undef SSHDIST_APPS_CERTUTILS_P12MAKE
#undef SSHDIST_EXTERNALKEY
#undef SSHDIST_EXTKEY_SOFT_ACCELERATOR_PROV
#undef SSHDIST_ASN1
#undef SSHDIST_CERT
#undef SSHDIST_CERT_CMP
#undef SSHDIST_CERT_CRMF
#undef SSHDIST_CERT_PKCS10
#undef SSHDIST_CERT_OCSP
#undef SSHDIST_SCEP_CLIENT
#undef SSHDIST_APPS_LDAPUTILS
#undef SSHDIST_LDAP
#undef SSHDIST_APPUTIL
#undef SSHDIST_APPUTIL_KEYUTIL
#undef SSHDIST_APPUTIL_PSYSTEM
#undef SSHDIST_VALIDATOR
#undef SSHDIST_VALIDATOR_PKCS
#undef SSHDIST_VALIDATOR_OCSP
#undef SSHDIST_VALIDATOR_HTTP
#undef SSHDIST_VALIDATOR_LDAP
#undef SSHDIST_VALIDATOR_CRL
/* undefine crypto functionality provided by MSCAPI */
#undef SSHDIST_CRYPT_ANSI_X917
#undef SSHDIST_CRYPT_ANSI_X962
#undef SSHDIST_CRYPT_ARCFOUR
#undef SSHDIST_CRYPT_DLKEX
#undef SSHDIST_CRYPT_DSA
#undef SSHDIST_CRYPT_EXPORT
#undef SSHDIST_CRYPT_SELF_TESTS
#undef SSHDIST_CRYPT_KEYBLOB
#undef SSHDIST_CRYPT_MD2
#undef SSHDIST_CRYPT_NAMELIST
#undef SSHDIST_CRYPT_RC2
#undef SSHDIST_CRYPT_RSA
#undef SSHDIST_CRYPT_SSHMACS
#undef SSHDIST_CRYPT_SSL3MAC
/*/ #undef SSHDIST_CRYPT_MODE_GCM */
#undef SSHDIST_CRYPT_DL_GENERATE

/* undefine functionality unsupported when MSCAPI is configured */
#undef SSHDIST_EAP_TLS
#undef SSHDIST_DIRECTORY_TLS
#undef SSHDIST_FUNCTIONALITY_TLS

#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */

#if defined SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifndef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
#define INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
#endif /* INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

#endif /* SSHINCLUDES_WIN32 */
