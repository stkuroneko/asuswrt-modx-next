/*
  This is a head file for malloc.c, and only export some functions usually used.
  You can extends the export functions from malloc.c, if you want more functions.

  @Hongliang.xin 2009-6-29

  Notes: 1. In malloc.c, predefined the thread-save macro
			#ifndef USE_LOCKS
			#define USE_LOCKS 1 
			#endif
		 2. Because the original malloc.c use the latest version of _WIN32_WINT,
		    which must be >= 0x0500, so in the malloc.c, we must force to define the
			_WIN32_WINT to 0x0500. Maybe it is not good.

			#define _WIN32_WINNT 0x0500 		    

*/

#ifndef _DLMALLOC_H__
#define _DLMALLOC_H__

/* for size_t definition */
#include <stddef.h>

//lint ++flb

extern "C" void* dlmalloc(size_t);
extern "C" void  dlfree(void *);
extern "C" void* dlcalloc(size_t, size_t);
extern "C" void* dlrealloc(void*, size_t);

//lint --flb

#endif // _DLMALLOC_H__