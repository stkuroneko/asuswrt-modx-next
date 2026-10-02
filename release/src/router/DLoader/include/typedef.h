#ifndef TYPEDEF_H
#define TYPEDEF_H


#include <stdio.h>
#include <stdint.h>
#include <sys/select.h>
#include <time.h>
#include <errno.h>
#include <iostream>
#include <unistd.h>

typedef uint32_t  DWORD;
typedef uint8_t * LPBYTE;
typedef uint32_t  BOOL;
typedef const char * LPCTSTR;
typedef uint8_t   BYTE;
typedef uint32_t  UINT;
typedef void *    LPVOID;
typedef uint16_t  WORD;
typedef char      _TCHAR;
typedef char      TCHAR;
typedef uint32_t HANDLE;
typedef char*     LPTSTR;
typedef uint32_t  ULONG;
typedef int32_t   LONG;
typedef DWORD * LPDWORD;
typedef unsigned short USHORT;
typedef int64_t __int64;
typedef uint64_t __uint64;
typedef int   WPARAM;
typedef void* LPARAM;

#define _MAX_PATH  260
#define MAX_PATH  260
#define WM_APP   0
#define TRUE     1
#define FALSE    0

#define INVALID_FILE_SIZE  (DWORD)(-1)

#define MAKEWORD(a, b)      ((WORD)(((BYTE)(a)) | ((WORD)((BYTE)(b))) << 8))
#define MAKELONG(a, b)      ((LONG)(((WORD)(a)) | ((DWORD)((WORD)(b))) << 16))
#define LOWORD(l)           ((WORD)(l))
#define HIWORD(l)           ((WORD)(((DWORD)(l) >> 16) & 0xFFFF))
#define LOBYTE(w)           ((BYTE)(w))
#define HIBYTE(w)           ((BYTE)(((WORD)(w) >> 8) & 0xFF))

#define UNUSED_ALWAYS(x)

#define _T(x)     x
#define OLE2T(x)  x
#define _stprintf sprintf
#define _tcscpy  strcpy
#define _tcscmp  strcmp
#define _tcsicmp strcasecmp
#define _tcsnicmp strncasecmp
#define _tcslen   strlen


#define SLEEP(x) {\
    struct timeval tv;\
    tv.tv_sec = (x)/1000;\
    tv.tv_usec = ((x)%1000)*1000;\
    select(0, NULL, NULL, NULL, &tv);\
}

static void _sleep(int msec)
{
    struct timespec tv;
    int rval;
    tv.tv_sec = (time_t)(msec/1000);
    tv.tv_nsec = (msec%1000)*1000;
    while(1)
    {
        rval = nanosleep(&tv, &tv);
        if(rval == 0)
            return;
        else if(errno == EINTR)
            continue;
        else
            return;
    }
    return;
}


inline void _StrTrim(std::string& buffer, const std::string& trimChars)
{
    std::string::size_type first = buffer.find_first_not_of(trimChars);
    std::string::size_type last = buffer.find_last_not_of(trimChars);
    if (first == std::string::npos)
        buffer.clear();
    else if (first <= last)
        buffer = buffer.substr(first, (last+1)-first);
}

inline void StrTrim(std::string& buffer)
{
    std::string trimChars = " \t\r\n";
    _StrTrim(buffer,trimChars);
}

#define MIPS_64_
static unsigned long long GetCycleCount()
{ 
    return 0ULL; 
    printf("Enter: %s\n", __func__);
     unsigned long long temp;
#ifdef MIPS_64_
     __asm__ __volatile__("mfc0 %0, $9; nop":"=r"(temp));
#else
     unsigned int low, high;
     __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high));
     temp = high;
     temp <<= 32;
     temp += low;
#endif
     return temp;
};

inline char* strlwr( char* str )
{
    char* orig = str;
    // process the string
    for ( ; *str != '\0'; str++ )
        *str = tolower(*str);
    return orig;
}

inline char* strupr( char* str )
{
    char* orig = str;
    // process the string
    for ( ; *str != '\0'; str++ )
        *str = toupper(*str);
    return orig;
}

int delete_dir(const char * dirname);

unsigned long GetTickCount();

#endif // TYPEDEF_H
