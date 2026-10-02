/**
   @copyright
   Copyright (c) 2011 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Transform Buffer - Public API of Transform Buffer service
*/

#ifndef TRANSFORM_BUFFER_H
#define TRANSFORM_BUFFER_H

#include "public_defs.h"

/**
   Maximum number of IOVs
*/
#define TRANSFORM_BUFFER_MAX_IOV_LEN 36

/**
  Structure of transform IOV
*/
typedef struct TransformIovRec
{
    unsigned char *data;
    unsigned int len;
} TransformIovecStruct, *TransformIovec;

/**
   Structure of transform buffer.

    <CODE>
   +--------------------------------------------------------------------------+
   |                            total space                                   |
   |                            (total_len)                                   |
   |<------------------------------------------------------------------------>|
   |               |                    data space                            |
   |               |             (total_len - data_offset)                    |
   |               |<-------------------------------------------------------->|
   |  offset area  |    data area      |            free space                |
   | (data_offset) |    (data_len)     | (total_len - data_len - data_offset) |
   |<------------->|<----------------->|<------------------------------------>|
   </CODE>

*/
typedef struct TransformBufferRec
{
    /* Length of data (real data stored to IOVs) */
    unsigned int data_len;

    /* Data offset (offset where real data begins) */
    unsigned int data_offset;

    /* Total length (buffering capacity of all IOVs) */
    unsigned int total_len;

    /* Number of populated IOVs */
    unsigned int iov_len;

    /* IOVs */
    TransformIovecStruct iov[TRANSFORM_BUFFER_MAX_IOV_LEN];

    union
  {
      /* Variables used for vector iteration */
      struct
    {
        unsigned int len;
        unsigned int iov_num;
        TransformIovecStruct iov;
      } vector_iter;

      /* Variables used for block iteration */
      struct
    {
        unsigned int len;
        unsigned int iov_num;
        TransformIovecStruct iov;

        unsigned int offset;
        unsigned char *buf;
        unsigned int size;
        unsigned int write_offset;
        unsigned int write_len;
        bool do_copy;
      } block_iter;

      /* Variables used for data iteration */
      struct
    {
        unsigned int len;
        unsigned int iov_num;
        TransformIovecStruct iov;
        unsigned int offset;
      } data_iter;

    } u;

} TransformBufferStruct, *TransformBuffer;


/* *************************** Public functions ******************************/

/**
   Function initializes the transform buffer.

   @param tbuf
   The transform buffer
*/
void
transform_buffer_init(
        TransformBuffer tbuf);

/**
   Function gets number of iovs currently used in transform buffer.

   @param tbuf
   The transform buffer

   @return
   The number of iovs
*/
unsigned int
transform_buffer_get_iov_len(
        TransformBuffer tbuf);

/**
   Function set data offset of the transform buffer.

   @param tbuf
   The transform buffer

   @param offset
   The data offset
*/
void
transform_buffer_set_data_offset(
        TransformBuffer tbuf,
        unsigned int offset);

/**
   Function increments data length of transform buffer. This function can be
   used when data is added to the end of the data. The function assumes that
   transform buffer contains enough free space in order that incrementation
   can be done.

   @param tbuf
   The transform buffer

   @param len
   The length
*/
void
transform_buffer_inc_data_len(
        TransformBuffer tbuf,
        unsigned int len);

/**
   Function decrements data length of transform buffer. This function can be
   used when data is removed from the end of the data. Function assumes that
   transform buffer contains enough data in order that decrementation can be
   done.

   @param tbuf
   The transform buffer

   @param len
   The length
*/
void
transform_buffer_dec_data_len(
        TransformBuffer tbuf,
        unsigned int len);

/**
   Function adjusts data offset of transform buffer. This function can be
   used when data is added or removed at the start of the data. If len is
   positive data_offset is incremented and data_len is decremented in
   transform buffer (Remove case). If len is negative data_offset is
   decremented and data_len is incremented in transform buffer (Add case).
   In both cases the function assumes that transform buffer contains enough
   free space or data to make adjustment.

   @param tbuf
   The transform buffer

   @param len
   The length
*/
void
transform_buffer_adjust_data_offset(
        TransformBuffer tbuf,
        int len);

/**
   Function gets how much data is stored to transform buffer.

   @param tbuf
   The transform buffer

   @return
   The data length
*/
unsigned int
transform_buffer_get_data_len(
        TransformBuffer tbuf);

/**
   Function gets the offset where data begins in transform buffer.

   @param tbuf
   The transform buffer

   @return
   The staring offset of data
*/
unsigned int
transform_buffer_get_data_offset(
        TransformBuffer tbuf);

/**
   Function gets the space available for data.

   @param tbuf
   The transform buffer

   @return
   The length of data space
*/
unsigned int
transform_buffer_get_data_space(
        TransformBuffer tbuf);

/**
   Function gets the total length of transform buffer from offset.

   @param tbuf
   The transform buffer

   @param offset
   The offset (from the beginning of iovs)

   @return
   The total length
*/
unsigned int
transform_buffer_get_total_len(
        TransformBuffer tbuf,
        unsigned int offset);

/**
   Function adds all iovs from source transform buffer to destination transform
   buffer which are inside data range (data_offset + offset .. len). Function
   will adjust iov's data pointer or len value if starting place is not at the
   beginning of source iov or if length is smaller than source iov.

   @param tbuf_dst
   The destination transform buffer

   @param tbuf_src
   The source transform buffer

   @param offset
   The offset where adding starts (relative to tbuf->data_offset)

   @param len
   The length
*/
void
transform_buffer_add_data_iovs(
        TransformBuffer tbuf_dst,
        TransformBuffer tbuf_src,
        unsigned int offset,
        unsigned int len);

/**
   Function will return first iov containing data from transform buffer.

   @param tbuf
   The transform buffer

   @param iov
   The iov where data is returned

   @param offset
   The offset where data starts from the beginning of iov.
*/
void
transform_buffer_get_first_data_iov(
        TransformBuffer tbuf,
        TransformIovec iov,
        unsigned int *offset);

/**
   Function will return all data stored to transform buffer. Data is always
   returned at the beginning of first iov (doesn't contain data_offset of
   transform buffer) and data length in all iovs is same than data length of
   transform buffer.

   @param tbuf
   The transform buffer

   @param iov
   The iov where data is returned

   @param iov_len
   The number of iovs
*/
void
transform_buffer_get_data_iovs(
        TransformBuffer tbuf,
        TransformIovec iov,
        unsigned int *iov_len);

/**
   Function will return requested length of data space in transform buffer.
   Data is always returned at the beginning of first iov (doesn't contain
   data_offset of transform buffer) and data length in all iovs is same than
   requested length.

   @param tbuf
   The transform buffer

   @param len
   The requested length of data space

   @param iov
   The iov where data is returned

   @param iov_len
   The number of iovs
*/
void
transform_buffer_get_data_space_iovs(
        TransformBuffer tbuf,
        unsigned int len,
        TransformIovec iov,
        unsigned int *iov_len);

/**
   Function will trim transform buffer by removing all iovs which doesn't
   contain any data. Removed iovs are returned to the caller via iov and
   iov_len arguments.

   @param tbuf
   The transform buffer

   @param iov
   The pointer to the first iov

   @param iov_len
   The number of removed iovs
*/
void
transform_buffer_trim_data_iovs(
        TransformBuffer tbuf,
        TransformIovec iov,
        unsigned int *iov_len);

/**
   Function will add new data iov to the transform buffer. Function will
   assumes that there is at least one free iov available in transform buffer.
   Function will increment data_len and total_len of transform buffer.

   @param tbuf
   The transform buffer

   @param iov
   The iov
*/
void
transform_buffer_insert_data_iov(
        TransformBuffer tbuf,
        TransformIovec iov);

/**
   Function will add new iov to the transform buffer. Function will assumes
   that there is at least one free iov available in transform buffer.
   Function will increment total_len of transform buffer but doesn't change
   data_len.

   @param tbuf
   The transform buffer

   @param data
   The data pointer

   @param len
   The length of data
*/
void
transform_buffer_add_iov(
        TransformBuffer tbuf,
        unsigned char *data,
        unsigned int len);

/**
   Function will get all iovs used in the transform buffer.

   @param tbuf
   The transform buffer

   @param iov
   The pointer to the first iov

   @param iov_len
   The number of iovs
*/
void
transform_buffer_get_iovs(
        TransformBuffer tbuf,
        TransformIovec iov,
        unsigned int *iov_len);

/**
   Function gets len bytes of data stored to transform buffer starting from
   tbuf->data_offset + offset. Offset + len should not exceed tbuf->data_len.
   Function will return pointer to data area of transform buffer if data is
   stored to continuous buffer. Otherwise function will copy data to buffer
   provided by caller and function will return pointer to this buffer.

   @param tbuf
   The transform buffer

   @param offset
   The offset where data starts (relative to tbuf->data_offset)

   @param data_buf
   The data buffer

   @param len
   The data length

   @return
   Returns pointer to the data in successful case and otherwise NULL.
*/
unsigned char *
transform_buffer_get_data(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned char *data_buf,
        unsigned int len);

/**
   Function reads len bytes of data stored to transform buffer starting from
   tbuf->data_offset + offset. Offset + len should not exceed tbuf->data_len.

   @param tbuf
   The transform buffer

   @param offset
   The offset where reading starts (relative to tbuf->data_offset)

   @param data
   Read data

   @param len
   The data length
*/
void
transform_buffer_read_data(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned char *data,
        unsigned int len);

/**
   Function adds len bytes of data into transform buffer. New data is stored
   at the end of current data region (data_offset + data_len).  Function will
   increment data_len variable of transform buffer. Function assumes that there
   is enough space for addition.

   @param tbuf
   The transform buffer

   @param data
   The data

   @param len
   The data length
*/
void
transform_buffer_add_data(
        TransformBuffer tbuf,
        unsigned char *data,
        unsigned int len);

/**
   Function adds len bytes of data into transform buffer. New data is stored at
   offset area located at front of current data region (data_offset - len).
   Function will increment data_len variable and decrement data_offset variable
   of transform buffer. Function assumes that there is enough space for
   addition.

   @param tbuf
   The transform buffer

   @param data
   The data

   @param len
   The data length
*/
void
transform_buffer_add_offset_data(
        TransformBuffer tbuf,
        unsigned char *data,
        unsigned int len);

/**
   Function resets vector iteration.

   @param tbuf
   The transform buffer

   @param offset
   The offset where iteration starts (relative to tbuf->data_offset)

   @param iteration_len
   The iteration len

   @return
   Returns true in successful case and otherwise false.
*/
bool
transform_buffer_vector_iteration_reset(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned int iteration_len);

/**
   Function get next data vector during vector iteration.

   @param tbuf
   The transform buffer

   @param vector
   The next vector

   @param len
   The length of vector

   @return
   Returns true in there was vector available and otherwise false.
*/
bool
transform_buffer_vector_iteration_next(
        TransformBuffer tbuf,
        unsigned char **vector,
        unsigned int *len);

/**
   Function resets block iteration.

   @param tbuf
   The transform buffer

   @param offset
   The offset where iteration starts (relative to tbuf->data_offset)

   @param iteration_len
   The iteration len

   @param block_size
   The block size

   @param block_buf
   The block buffer

   @param do_copy
   The copying flag

   @return
   Returns true in successful case and otherwise false.
*/
bool
transform_buffer_block_iteration_reset(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned int iteration_len,
        unsigned int block_size,
        unsigned char *block_buf,
        bool do_copy);

/**
   Function get next data block(s) during block iteration.

   @param tbuf
   The transform buffer

   @param block
   The data block(s)

   @param len
   The length (multiple of blocks or smaller than one block if last
   data portion)

   @return
   Returns true in there was data blocks available and otherwise false.
*/
bool
transform_buffer_block_iteration_next(
        TransformBuffer tbuf,
        unsigned char **block,
        unsigned int *len);

/**
   Function writes block(s) to transform buffer whenever required during
   block iteration.

   @param tbuf
   The transform buffer
*/
void
transform_buffer_block_iteration_write(
        TransformBuffer tbuf);

/**
   Function resets data iteration.

   @param tbuf
   The transform buffer

   @param offset
   The offset where iteration starts (relative to tbuf->data_offset)

   @param iteration_len
   The iteration len

   @return
   Returns true in successful case and otherwise false.
*/
bool
transform_buffer_data_iteration_reset(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned int iteration_len);

/**
   Function get next data part during data iteration. Function will return
   pointer to the data of transform buffer if data is stored in continuous iov
   segment. Otherwise function will copy data to the buffer provided by the
   caller and returns pointer to the data buffer. Function assumes that data
   buffer is big enough for the data. Function will automatically increment
   data iteration point with bytes of len.

   @param tbuf
   The transform buffer

   @param data
   The data buffer

   @param len
   The length of data

   @return
   Returns pointer to the data if there was data available and otherwise NULL.
*/
unsigned char *
transform_buffer_data_iteration_next(
        TransformBuffer tbuf,
        unsigned char *data,
        unsigned int len);

/**
   Function will increment data iteration point with bytes of len.

   @param tbuf
   The transform buffer

   @param len
   The incrementation length

   @return
   Returns true if incrementation was successful and otherwise false.
*/
bool
transform_buffer_data_iteration_inc(
        TransformBuffer tbuf,
        unsigned int len);

/**
   Function will decrement data iteration point with bytes of len.

   @param tbuf
   The transform buffer

   @param len
   The decrementation length

   @return
   Returns true if decrementation was successful and otherwise false.
*/
bool
transform_buffer_data_iteration_dec(
        TransformBuffer tbuf,
        unsigned int len);



/**
   Function copies len bytes of data stored to transform buffer
   tbuf_src starting from tbuf_src->data_offset + offset_src to
   transform buffer tbuf_dst. The offset_src + len should not exceed
   tbuf_src->data_len. The data is copied to
   tbuf_dst->data_offset. The tbuf_dst->data_len is increased by len.

   @param tbuf_dst
   The destination transform buffer

   @param tbuf_src
   The source transform buffer

   @param offset_src
   The offset where reading starts (relative to tbuf_src->data_offset)

   @param len
   The data length
*/
void
transform_buffer_copy(
        TransformBuffer tbuf_dst,
        TransformBuffer tbuf_src,
        unsigned int offset_src,
        unsigned int len);

#endif /* TRANSFORM_BUFFER_H */
