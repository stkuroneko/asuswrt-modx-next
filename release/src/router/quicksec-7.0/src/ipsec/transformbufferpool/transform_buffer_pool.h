/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Transform buffer pool module. This module maintains a freelist of
   transform buffer structures and fixed sized data segments.
*/

#include "transform_buffer.h"

#ifndef TRANSFORM_BUFFER_POOL_H
#define TRANSFORM_BUFFER_POOL_H

/** Buffer manager */
typedef struct TransformBufferPoolRec *TransformBufferPool;

/** Transform buffer segment size */
#ifndef TRANSFORM_BUFFER_SEGMENT_SIZE
#define TRANSFORM_BUFFER_SEGMENT_SIZE 2000
#endif

/** Transform buffer freelist size */
#ifndef TRANSFORM_BUFFER_POOL_BUFFER_FREELIST_SIZE
#define TRANSFORM_BUFFER_POOL_BUFFER_FREELIST_SIZE 1024
#endif

/** Segment freelist size */
#define TRANSFORM_BUFFER_POOL_SEGMENT_FREELIST_SIZE \
  TRANSFORM_BUFFER_POOL_BUFFER_FREELIST_SIZE


/**
   Free transform buffer.
 */
void
transform_buffer_pool_buffer_free(TransformBufferPool buffer_pool,
                                  TransformBuffer transform_buffer);

/**
   Allocate a transform buffer with total length of atleast 'offset' and
   'size'. This function allocates transform buffer and enough buffer
   segments from buffer pool's freelists.
 */
TransformBuffer
transform_buffer_pool_buffer_alloc(TransformBufferPool buffer_pool,
                                   size_t offset,
                                   size_t size);

/**
   Trim transform buffer to current data length. This frees unused buffer
   segments and returns them to buffer pool's freelist, and sets the transform
   buffer 'total_len' and 'iov_len' fields to the resulting values.
 */
void
transform_buffer_pool_buffer_trim(TransformBufferPool buffer_pool,
                                  TransformBuffer transform_buffer);

/**
   Linearize transform buffer to linear buffer from requested data 'size'.
   This function copies the transform buffer's segments to the linear buffer
   'linear'. It is expected that the caller supplied linear buffer 'linear'
   is large enough.
 */
void
transform_buffer_pool_buffer_linearize(TransformBuffer transform_buffer,
                                       size_t size,
                                       unsigned char *linear);

/**
   Uninitialize transform buffer pool.
 */
void
transform_buffer_pool_uninit(TransformBufferPool *buffer_pool_p);

/**
   Initialize transform buffer pool.
*/
bool transform_buffer_pool_init(TransformBufferPool *buffer_pool_p);

#endif /* TRANSFORM_BUFFER_POOL_H */
