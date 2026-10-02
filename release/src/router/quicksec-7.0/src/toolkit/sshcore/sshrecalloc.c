/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Reallocate table to bigger or smaller.
*/

#include "sshincludes.h"

/* Realloc ptr table to bigger. The ptr points to an address containing the
   pointer to the beginning of the table. The ptr is modified to contain new
   address if this call is successful. The same value is also returned. The
   cnt_ptr is a pointer to the integer containing the number of items in the
   table and it will be modified to contain the new number of items. The table
   is reallocated to contain new_cnt number of items of size item_size. The
   newly allocated items are filled with zeros. If the realloc fails, then
   *ptr and *cnt_ptr are left untouched and false is returned. If operation was
   successful then it returns true. */
bool ssh_recalloc(void *ptr, uint32_t *cnt_ptr, uint32_t new_cnt,
                     size_t item_size)
{
    void *new_ptr;
    size_t old_size, new_size;

    old_size = (*cnt_ptr) * item_size;
    new_size = new_cnt * item_size;

    new_ptr = ssh_realloc(*(void **) ptr, old_size, new_size);
    if (new_ptr == NULL)
      return false;

    if (old_size < new_size)
      memset(((unsigned char *) (new_ptr)) + old_size, 0, new_size - old_size);

    *cnt_ptr = new_cnt;
    *(void **) ptr = new_ptr;
    return true;
}
