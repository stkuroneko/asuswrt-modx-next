/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Versions of malloc and friends that check their results, and never return
   failure (they call fatal if they encounter an error).
*/

#include "sshincludes.h"

/* Note, these functions can be called from other threads also, thus
   cannot use any debugging macros (they can only be called from the
   SSH main thread).  Also note that you cannot call any other SSH
   library functions that are not marked thread safe from this file */
#undef SSH_DEBUG_MODULE

#undef malloc
#undef calloc
#undef realloc
#undef free
#undef memdup
#undef strdup

#ifdef SSH_DEBUG_MALLOC
#include "sshgetput.h"
#define SSH_DEBUG_MALLOC_SIZE_BEFORE    8
#define SSH_DEBUG_MALLOC_SIZE_AFTER     4
#define SSH_DEBUG_MALLOC_MAGIC_IN_USE   0x21041999
#define SSH_DEBUG_MALLOC_MAGIC_FREED    0x13061968
#define SSH_DEBUG_MALLOC_MAGIC_AFTER    0x99190214

#ifndef SSH_DEBUG_MALLOC_HEAVY
#define SSH_DEBUG_MALLOC_HEAVY
#endif /* not SSH_DEBUG_MALLOC_HEAVY */
#endif /* SSH_DEBUG_MALLOC */



















































































































/* Callback that is called if set when the malloc runs out of memory */
SSH_BSS_INITONCE
bool (*ssh_malloc_failed_cb)(void);

void *ssh_malloc(size_t size)
{
    void *ptr;

    if (size > XMALLOC_MAX_SIZE)
      return NULL;

    if (size == 0)
      size = 1;
#ifdef SSH_DEBUG_MALLOC
    while (1)
    {
        ptr = (void *)malloc((size_t)
                             size +
                             SSH_DEBUG_MALLOC_SIZE_BEFORE +
                             SSH_DEBUG_MALLOC_SIZE_AFTER);
        if (ptr != NULL)
          break;

        if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
          return NULL;
    }

    SSH_PUT_32BIT(ptr, size);
    SSH_PUT_32BIT((unsigned char *) ptr + 4, SSH_DEBUG_MALLOC_MAGIC_IN_USE);
    SSH_PUT_32BIT((unsigned char *) ptr + size + SSH_DEBUG_MALLOC_SIZE_BEFORE,
                  SSH_DEBUG_MALLOC_MAGIC_AFTER);
    ptr = (unsigned char *) ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE;
#ifdef SSH_DEBUG_MALLOC_HEAVY
    /* don't memset memory with purify, as it would mark the memory as
       "initialized" */
#ifndef WITH_PURIFY
    memset(ptr, 'A', size);
#endif /* WITH_PURIFY */
#endif /* SSH_DEBUG_MALLOC_HEAVY */
#else /* SSH_DEBUG_MALLOC */
    while (1)
    {
        ptr = (void *)malloc((size_t) size);
        if (ptr != NULL)
          break;
        if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
          return NULL;
    }
#endif /* SSH_DEBUG_MALLOC */
    return ptr;
}

void *ssh_calloc(size_t nitems, size_t size)
{
    void *ptr;

    if (nitems == 0)
      nitems = 1;
    if (size == 0)
      size = 1;

    if (size * nitems > XMALLOC_MAX_SIZE)
      return NULL;

#ifdef SSH_DEBUG_MALLOC
    while (1)
    {
        ptr = (void *)malloc(((size_t) nitems * (size_t) size) +
                             SSH_DEBUG_MALLOC_SIZE_BEFORE +
                             SSH_DEBUG_MALLOC_SIZE_AFTER);
        if (ptr != NULL)
          break;
        if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
          return NULL;
    }

    memset((unsigned char *) ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE,
           0, (nitems * size));
    SSH_PUT_32BIT(ptr, (size * nitems));
    SSH_PUT_32BIT((unsigned char *) ptr + 4, SSH_DEBUG_MALLOC_MAGIC_IN_USE);
    SSH_PUT_32BIT((unsigned char *) ptr + (size * nitems) +
                  SSH_DEBUG_MALLOC_SIZE_BEFORE,
                  SSH_DEBUG_MALLOC_MAGIC_AFTER);
    ptr = (unsigned char *) ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE;
#else /* SSH_DEBUG_MALLOC */
    while (1)
    {
        ptr = (void *)calloc((size_t) nitems, (size_t) size);
        if (ptr != NULL)
          break;
        if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
          return NULL;
    }
#endif /* SSH_DEBUG_MALLOC */
    return ptr;
}

void *ssh_realloc(void *ptr,
                  size_t old_size, size_t new_size)
{
    void *new_ptr = NULL;

    if (ptr == NULL)
      return ssh_malloc(new_size);

    if (new_size > XMALLOC_MAX_SIZE)
      return NULL;

    if (new_size == 0)
      new_size = 1;

#ifdef SSH_DEBUG_MALLOC
    if (SSH_GET_32BIT((unsigned char *) ptr - 4) !=
        SSH_DEBUG_MALLOC_MAGIC_IN_USE)
    {
        if (SSH_GET_32BIT((unsigned char *) ptr - 4) ==
            SSH_DEBUG_MALLOC_MAGIC_FREED)
          ssh_fatal("Reallocating block that is already freed");

        ssh_fatal("Reallocating block that is either not mallocated, "
                  "or whose magic number before the object was overwritten");
    }
    else
    {
        size_t osize;

        osize = SSH_GET_32BIT((unsigned char *) ptr -
                              SSH_DEBUG_MALLOC_SIZE_BEFORE);

        /* Zero check here for use of ssh_xrealloc (where the API does
           not know old size. One should not call ssh_realloc(p, 0,
           new), even if that now happens to work. */

        if (old_size != 0 && old_size != osize)
          ssh_fatal("Application concept of old size does not match "
                    "the block being reallocated: %zd vs %zd",
                    old_size, osize);

        if (SSH_GET_32BIT((unsigned char *) ptr + osize) !=
            SSH_DEBUG_MALLOC_MAGIC_AFTER)
          ssh_fatal("Reallocating block whose magic number after the "
                    "object was overwritten");

        /* Mark the old block freed */
        SSH_PUT_32BIT((unsigned char *) ptr - 4, SSH_DEBUG_MALLOC_MAGIC_FREED);
        SSH_PUT_32BIT((unsigned char *) ptr + osize,
                      SSH_DEBUG_MALLOC_MAGIC_FREED);

        while (1)
        {
            new_ptr = (void *)realloc((unsigned char *) ptr -
                                      SSH_DEBUG_MALLOC_SIZE_BEFORE,
                                      (size_t) new_size +
                                      SSH_DEBUG_MALLOC_SIZE_BEFORE +
                                      SSH_DEBUG_MALLOC_SIZE_AFTER);
            if (new_ptr != NULL)
              break;
            if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
              return NULL;
        }

        SSH_PUT_32BIT(new_ptr, new_size);
        SSH_PUT_32BIT((unsigned char *) new_ptr + 4,
                      SSH_DEBUG_MALLOC_MAGIC_IN_USE);
        SSH_PUT_32BIT((unsigned char *) new_ptr + new_size +
                      SSH_DEBUG_MALLOC_SIZE_BEFORE,
                      SSH_DEBUG_MALLOC_MAGIC_AFTER);
        new_ptr = (unsigned char *) new_ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE;
    }
#else /* SSH_DEBUG_MALLOC */
    while (1)
    {
        new_ptr = (void *)realloc(ptr, (size_t) new_size);
        if (new_ptr != NULL)
          break;
        if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
          return NULL;
    }
#endif /* SSH_DEBUG_MALLOC */
    return new_ptr;
}

/* coverity[ -tainted_data_sink : arg-0 ] */
void ssh_free(void *ptr)
{
#ifdef SSH_DEBUG_MALLOC
    if (ptr != NULL)
    {
        size_t size;

        if (SSH_GET_32BIT((unsigned char *) ptr - 4) !=
            SSH_DEBUG_MALLOC_MAGIC_IN_USE)
        {
            if (SSH_GET_32BIT((unsigned char *) ptr - 4) ==
                SSH_DEBUG_MALLOC_MAGIC_FREED)
              ssh_fatal("Freeing block that is already freed");
            ssh_fatal(
                    "Freeing block that is either not mallocated, "
                    "or whose magic number before the object was overwritten");
        }

        size = SSH_GET_32BIT((unsigned char *) ptr -
                             SSH_DEBUG_MALLOC_SIZE_BEFORE);
        if (SSH_GET_32BIT((unsigned char *) ptr + size) !=
            SSH_DEBUG_MALLOC_MAGIC_AFTER)
          ssh_fatal("Freeing block whose magic number after the object "
                    "was overwritten");

        /* Mark the old block freed */
        SSH_PUT_32BIT((unsigned char *) ptr - 4, SSH_DEBUG_MALLOC_MAGIC_FREED);
        SSH_PUT_32BIT((unsigned char *) ptr + size,
                      SSH_DEBUG_MALLOC_MAGIC_FREED);
#ifdef SSH_DEBUG_MALLOC_HEAVY
        SSH_CLEAR_MEMORY(ptr, size);
#endif /* SSH_DEBUG_MALLOC_HEAVY */
        free((unsigned char *) ptr - SSH_DEBUG_MALLOC_SIZE_BEFORE);
    }
#else /* SSH_DEBUG_MALLOC */
    if (ptr != NULL)
      free(ptr);
#endif /* SSH_DEBUG_MALLOC */
}

char *ssh_strdup(const char *p)
{
    const char *str;
    char *cp = NULL;

    if (p)
    {
        str = (const char *)p;
        if ((cp = ssh_malloc(strlen(str) + 1)) != NULL)
          strcpy(cp, str);
    }
    return cp;
}

void *ssh_memdup(const void *p, size_t len)
{
    const char *str = (const char *)p;
    char *cp = NULL;

    if (len < XMALLOC_MAX_SIZE)
    {
        if ((cp = ssh_malloc(len + 1)) != NULL)
        {
            memcpy(cp, str, (size_t)len);
            cp[len] = '\0';
        }
    }
    return (void *)cp;
}
