/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Transform buffer pool module. This module maintains a freelist of
   transform buffer structures and fixed sized data segments.
*/

#include "sshincludes.h"
#include "transform_buffer_pool.h"

#define SSH_DEBUG_MODULE "TransformBufferPool"


/*********************** Internal datatypes *********************************/

/** Transform buffer segment */
typedef struct TransformBufferSegmentRec *TransformBufferSegment;
typedef struct TransformBufferSegmentRec
{
    char buf[TRANSFORM_BUFFER_SEGMENT_SIZE];
    TransformBufferSegment next;
#ifdef DEBUG_LIGHT
    bool in_use;
#endif /* DEBUG_LIGHT */
} TransformBufferSegmentStruct;

/** Transform buffer wrapper */
typedef struct TransformBufferWrapperRec *TransformBufferWrapper;
typedef struct TransformBufferWrapperRec
{
    TransformBufferStruct transform_buffer;
    TransformBufferWrapper next;
#ifdef DEBUG_LIGHT
    bool in_use;
#endif /* DEBUG_LIGHT */
} TransformBufferWrapperStruct;

/** Buffer manager */
typedef struct TransformBufferPoolRec
{
    TransformBufferSegment segment_freelist;
    TransformBufferWrapper buffer_freelist;
#ifdef DEBUG_LIGHT
    int num_seg_allocated;
    int num_buffer_allocated;
#endif /* DEBUG_LIGHT */
} TransformBufferPoolStruct;


/************************ Transform buffer alloc / free *********************/

void
transform_buffer_pool_buffer_free(
        TransformBufferPool buffer_pool,
        TransformBuffer transform_buffer)
{
    TransformBufferWrapper buffer;
    TransformBufferSegment seg;
    TransformIovecStruct iov[TRANSFORM_BUFFER_MAX_IOV_LEN];
    unsigned int iov_len;
    int i;

    /** Get iovs from transform buffer */
    transform_buffer_get_iovs(transform_buffer, iov, &iov_len);

    /** Return segments to freelist */
    for (i = 0; i < iov_len; i++)
    {
        seg = (TransformBufferSegment) iov[i].data;
#ifdef DEBUG_LIGHT
        SSH_ASSERT(seg->in_use == true);
        seg->in_use = false;
        SSH_ASSERT(buffer_pool->num_seg_allocated > 0);
        buffer_pool->num_seg_allocated--;
#endif /* DEBUG_LIGHT */
        seg->next = buffer_pool->segment_freelist;
        buffer_pool->segment_freelist = seg;
    }

    /** Return buffer to freelist */
    buffer = (TransformBufferWrapper) transform_buffer;
#ifdef DEBUG_LIGHT
    SSH_ASSERT(buffer->in_use == true);
    buffer->in_use = false;
    SSH_ASSERT(buffer_pool->num_buffer_allocated > 0);
    buffer_pool->num_buffer_allocated--;
#endif /* DEBUG_LIGHT */
    buffer->next = buffer_pool->buffer_freelist;
    buffer_pool->buffer_freelist = buffer;
}

TransformBuffer
transform_buffer_pool_buffer_alloc(
        TransformBufferPool buffer_pool,
        size_t offset,
        size_t size)
{
    TransformBufferWrapper buffer;
    TransformBufferSegment seg;
    unsigned int iov_len;
    size_t buffer_size;
    size_t len;

    /** Allocate buffer from freelist */
    buffer = buffer_pool->buffer_freelist;
    if (buffer == NULL)
    {
        return NULL;
    }

    buffer_pool->buffer_freelist = buffer->next;

    SSH_ASSERT(buffer->in_use == false);

    memset(buffer, 0, sizeof(*buffer));
#ifdef DEBUG_LIGHT
    buffer->in_use = true;
    buffer_pool->num_buffer_allocated++;
#endif /* DEBUG_LIGHT */

    /** Calculate total buffer size */
    buffer_size = offset + size;

    /** Allocate segments to cover requested total size */
    for (len = 0, iov_len = 0; len < buffer_size; iov_len++)
    {
        if (iov_len >= TRANSFORM_BUFFER_MAX_IOV_LEN)
        {
            transform_buffer_pool_buffer_free(
                    buffer_pool,
                    &buffer->transform_buffer);
            return NULL;
        }

        seg = buffer_pool->segment_freelist;
        if (seg == NULL)
        {
            transform_buffer_pool_buffer_free(
                    buffer_pool,
                    &buffer->transform_buffer);
            return NULL;
        }
        buffer_pool->segment_freelist = seg->next;

#ifdef DEBUG_LIGHT
        SSH_ASSERT(seg->in_use == false);
        seg->in_use = true;
        buffer_pool->num_seg_allocated++;
#endif /* DEBUG_LIGHT */

        transform_buffer_add_iov(
                &buffer->transform_buffer,
                (unsigned char *) seg->buf,
                TRANSFORM_BUFFER_SEGMENT_SIZE);
        len += TRANSFORM_BUFFER_SEGMENT_SIZE;
    }

    /** Adjust data offset of transform buffer */
    transform_buffer_set_data_offset(&buffer->transform_buffer, offset);

    return &buffer->transform_buffer;
}


/**************************** Transform buffer trim *************************/

static void
transform_buffer_pool_free_seg(
        TransformBufferPool buffer_pool,
        TransformBufferWrapper buffer,
        unsigned char *data)
{
    /* NOTE: If this module is to be used in as a more generic module,
       then the segment should be looked up in 'buffer' by 'data' pointer. */
    TransformBufferSegment seg = (TransformBufferSegment) data;

#ifdef DEBUG_LIGHT
    SSH_ASSERT(seg->in_use == true);
    seg->in_use = false;
    SSH_ASSERT(buffer_pool->num_seg_allocated > 0);
    buffer_pool->num_seg_allocated--;
#endif /* DEBUG_LIGHT */
    seg->next = buffer_pool->segment_freelist;
    buffer_pool->segment_freelist = seg;
}

void
transform_buffer_pool_buffer_trim(
        TransformBufferPool buffer_pool,
        TransformBuffer transform_buffer)
{
    TransformBufferWrapper buffer = (TransformBufferWrapper) transform_buffer;
    TransformIovecStruct iov[TRANSFORM_BUFFER_MAX_IOV_LEN];
    unsigned int iov_len;
    int i;

    /** Trim transform buffer */
    transform_buffer_trim_data_iovs(transform_buffer, iov, &iov_len);

    /** Free unused segments from transform buffer */
    for (i = 0; i < iov_len; i++)
    {
        transform_buffer_pool_free_seg(buffer_pool, buffer, iov[i].data);
    }
}


/************************** Transform buffer linearize **********************/

void
transform_buffer_pool_buffer_linearize(
        TransformBuffer transform_buffer,
        size_t size,
        unsigned char *linear)
{
    /** Read data from transform buffer to linear buffer. Reading is done at
        the start of the data area of transform buffer. */
    transform_buffer_read_data(transform_buffer, 0, linear, size);
}


/*************************** Buffer manager init/uninit *********************/

void
transform_buffer_pool_uninit(
        TransformBufferPool *buffer_pool_p)
{
    TransformBufferSegment seg;
    TransformBufferWrapper buffer;

    SSH_DEBUG(SSH_D_HIGHOK,
              ("Transform Buffer Pool uninit: 0x%p",
               *buffer_pool_p));

    if (*buffer_pool_p != NULL)
    {
        TransformBufferPool buffer_pool = *buffer_pool_p;

        /** Free buffer segments from the freelist */
        while (buffer_pool->segment_freelist != NULL)
        {
            seg = buffer_pool->segment_freelist;
            buffer_pool->segment_freelist = seg->next;
            SSH_ASSERT(seg->in_use == false);
            ssh_free(seg);
        }

        /** Free transform buffers from the freelist */
        while (buffer_pool->buffer_freelist != NULL)
        {
            buffer = buffer_pool->buffer_freelist;
            buffer_pool->buffer_freelist = buffer->next;
            SSH_ASSERT(buffer->in_use == false);
            ssh_free(buffer);
        }

        SSH_ASSERT(buffer_pool->num_seg_allocated == 0);
        SSH_ASSERT(buffer_pool->num_buffer_allocated == 0);
        ssh_free(buffer_pool);
        *buffer_pool_p = NULL;
    }
}

bool
transform_buffer_pool_init(
        TransformBufferPool *buffer_pool_p)
{
    TransformBufferPool buffer_pool;
    TransformBufferSegment seg;
    TransformBufferWrapper buffer;
    int i;

    /** Allocate buffer manager structure */
    buffer_pool = ssh_calloc(1, sizeof(*buffer_pool));
    if (buffer_pool == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cannot get memory for Transform Buffer Pool context"));
        goto fail;
    }

    /** Fill buffer segment freelist */
    for (i = 0; i < TRANSFORM_BUFFER_POOL_SEGMENT_FREELIST_SIZE; i++)
    {
        seg = ssh_calloc(1, sizeof(*seg));
        if (seg == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Cannot get memory for segment"));
            goto fail;
        }

#ifdef DEBUG_LIGHT
        seg->in_use = false;
#endif /* DEBUG_LIGHT */
        seg->next = buffer_pool->segment_freelist;
        buffer_pool->segment_freelist = seg;
    }

    /** Fill transform buffer freelist */
    for (i = 0; i < TRANSFORM_BUFFER_POOL_BUFFER_FREELIST_SIZE; i++)
    {
        buffer = ssh_calloc(1, sizeof(*buffer));
        if (buffer == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Cannot get memory for buffer"));
            goto fail;
        }

#ifdef DEBUG_LIGHT
        buffer->in_use = false;
#endif /* DEBUG_LIGHT */
        buffer->next = buffer_pool->buffer_freelist;
        buffer_pool->buffer_freelist = buffer;
    }

    SSH_DEBUG(SSH_D_HIGHOK,
              ("Transform Buffer Pool init successful: 0x%p",
               buffer_pool));

    *buffer_pool_p = buffer_pool;

    return true;

   fail:

    if (buffer_pool != NULL)
    {
        transform_buffer_pool_uninit(&buffer_pool);
    }

    SSH_DEBUG(SSH_D_ERROR, ("Transform Buffer Pool init failed"));

    *buffer_pool_p = NULL;

    return false;
}
