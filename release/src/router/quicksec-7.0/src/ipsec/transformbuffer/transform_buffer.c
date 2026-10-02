/**
   @copyright
   Copyright (c) 2011 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Transform Buffer - Implementation of Transform Buffer service
*/

#include <stdio.h>
#include <string.h>

#include "transform_buffer.h"
#include "implementation_defs.h"


#define __DEBUG_MODULE__ TransformBuffer

/**************************** Initialization *********************************/

void
transform_buffer_init(
        TransformBuffer tbuf)
{
    tbuf->data_len = 0;
    tbuf->data_offset = 0;
    tbuf->iov_len = 0;
    tbuf->total_len = 0;
}

/**************************** Get used iovs *********************************/

unsigned int
transform_buffer_get_iov_len(
        TransformBuffer tbuf)
{
    return tbuf->iov_len;
}

/******************** Manipulation of data variables *************************/

void
transform_buffer_set_data_offset(
        TransformBuffer tbuf,
        unsigned int offset)
{
    ASSERT(tbuf->total_len >= offset);
    tbuf->data_offset = offset;
}

void
transform_buffer_inc_data_len(
        TransformBuffer tbuf,
        unsigned int len)
{
    tbuf->data_len += len;

    ASSERT(tbuf->total_len >= tbuf->data_len + tbuf->data_offset);
}

void
transform_buffer_dec_data_len(
        TransformBuffer tbuf,
        unsigned int len)
{
    ASSERT(tbuf->data_len >= len);

    tbuf->data_len -= len;
}

void
transform_buffer_adjust_data_offset(
        TransformBuffer tbuf,
        int len)
{
    if (len >= 0)
    {
        ASSERT(tbuf->data_len >= len);

        tbuf->data_len -= len;
        tbuf->data_offset += len;
    }
    else
    {
        ASSERT(((int) tbuf->data_offset) + len >= 0);

        tbuf->data_len -= len;
        tbuf->data_offset += len;
    }
}

unsigned int
transform_buffer_get_data_len(
        TransformBuffer tbuf)
{
    return tbuf->data_len;
}

unsigned int
transform_buffer_get_data_offset(
        TransformBuffer tbuf)
{
    return tbuf->data_offset;
}

unsigned int
transform_buffer_get_data_space(
        TransformBuffer tbuf)
{
    return tbuf->total_len - tbuf->data_offset;
}

unsigned int
transform_buffer_get_total_len(
        TransformBuffer tbuf,
        unsigned int offset)
{
    if (offset >= tbuf->total_len)
    {
        return 0;
    }
    else
    {
        return tbuf->total_len - offset;
    }
}

/******************** Find correct location from IOVs ************************/

static bool
transform_buffer_locate_iov(
        TransformIovec iov,
        unsigned int iov_len,
        unsigned int offset,
        unsigned int *ret_iov_num,
        unsigned int *ret_offset)
{
    int count;

    for (count = 0; count < iov_len; count++)
    {
        if (iov[count].len > offset)
        {
            *ret_iov_num = count;
            *ret_offset = offset;
            return true;
        }
        offset -= iov[count].len;
    }

    return false;
}

/************************ Storing data into IOVs *****************************/

static unsigned int
transform_buffer_set_iov(
        TransformBuffer tbuf,
        TransformIovec iov,
        unsigned int offset,
        unsigned int len)
{
    unsigned int tmp_len;

    if (offset == 0)
    {
        tbuf->iov[tbuf->iov_len].data = iov->data;
        tmp_len = iov->len;
    }
    else
    {
        tbuf->iov[tbuf->iov_len].data = iov->data + offset;
        tmp_len = iov->len - offset;
    }

    if (tmp_len > len)
    {
        tmp_len = len;
    }

    tbuf->iov[tbuf->iov_len].len = tmp_len;
    tbuf->data_len += tmp_len;
    tbuf->iov_len++;
    tbuf->total_len += tmp_len;

    ASSERT(tbuf->iov_len < TRANSFORM_BUFFER_MAX_IOV_LEN);

    return tmp_len;
}

void
transform_buffer_add_data_iovs(
        TransformBuffer tbuf_dst,
        TransformBuffer tbuf_src,
        unsigned int offset,
        unsigned int len)
{
    unsigned int tmp_offset;
    unsigned int src_count;

    if (len == 0)
    {
        return;
    }

    /* Locate correct source iov */
    if (transform_buffer_locate_iov(
                tbuf_src->iov,
                tbuf_src->iov_len,
                tbuf_src->data_offset + offset,
                &src_count,
                &tmp_offset) == false)
    {
        ASSERT(false);
        return;
    }

    /* Copy 1st iov */
    len -=
      transform_buffer_set_iov(
              tbuf_dst,
              &tbuf_src->iov[src_count],
              tmp_offset,
              len);

    /* Copy other iovs */
    while (len > 0)
    {
        src_count++;
        ASSERT(src_count < TRANSFORM_BUFFER_MAX_IOV_LEN);

        len -=
          transform_buffer_set_iov(
                  tbuf_dst,
                  &tbuf_src->iov[src_count],
                  0,
                  len);
    }
}

void
transform_buffer_insert_data_iov(
        TransformBuffer tbuf,
        TransformIovec iov)
{
    tbuf->iov[tbuf->iov_len].data = iov->data;
    tbuf->iov[tbuf->iov_len].len = iov->len;
    tbuf->data_len += iov->len;

    tbuf->iov_len++;
    tbuf->total_len += iov->len;

    ASSERT(tbuf->iov_len < TRANSFORM_BUFFER_MAX_IOV_LEN);
}

void
transform_buffer_get_first_data_iov(
        TransformBuffer tbuf,
        TransformIovec iov,
        unsigned int *offset)
{
    unsigned int src_count;
    unsigned data_len = tbuf->data_len;

    /* Locate correct source iov */
    if (transform_buffer_locate_iov(
                tbuf->iov,
                tbuf->iov_len,
                tbuf->data_offset,
                &src_count,
                offset) == false)
    {
        ASSERT(false);
        return;
    }

    iov->data = tbuf->iov[src_count].data + *offset;
    iov->len = tbuf->iov[src_count].len - *offset;

    if (iov->len >= data_len)
    {
        iov->len = data_len;
    }
}

void
transform_buffer_get_data_iovs(
        TransformBuffer tbuf,
        TransformIovec iov,
        unsigned int *iov_len)
{
    unsigned int tmp_offset;
    unsigned int src_count;
    unsigned data_len = tbuf->data_len;

    *iov_len = 0;

    if (data_len == 0)
    {
        return;
    }

    /* Locate correct source iov */
    if (transform_buffer_locate_iov(
                tbuf->iov,
                tbuf->iov_len,
                tbuf->data_offset,
                &src_count,
                &tmp_offset) == false)
    {
        ASSERT(false);
        return;
    }

    iov[*iov_len].data = tbuf->iov[src_count].data + tmp_offset;
    iov[*iov_len].len = tbuf->iov[src_count].len - tmp_offset;

    if (iov[*iov_len].len >= data_len)
    {
        iov[*iov_len].len = data_len;
        *iov_len = 1;
        return;
    }

    data_len -= iov[*iov_len].len;
    (*iov_len)++;
    src_count++;

    while (data_len > tbuf->iov[src_count].len)
    {
        data_len -= tbuf->iov[src_count].len;
        iov[(*iov_len)++] = tbuf->iov[src_count++];
    }

    iov[*iov_len].data = tbuf->iov[src_count].data;
    iov[*iov_len].len = data_len;
    (*iov_len)++;
}

void
transform_buffer_get_data_space_iovs(
        TransformBuffer tbuf,
        unsigned int len,
        TransformIovec iov,
        unsigned int *iov_len)
{
    unsigned int tmp_offset;
    unsigned int src_count;

    ASSERT(tbuf->total_len - tbuf->data_offset >= len);

    *iov_len = 0;

    if (len == 0)
    {
        return;
    }

    /* Locate correct source iov */
    if (transform_buffer_locate_iov(
                tbuf->iov,
                tbuf->iov_len,
                tbuf->data_offset,
                &src_count,
                &tmp_offset) == false)
    {
        ASSERT(false);
        return;
    }

    iov[*iov_len].data = tbuf->iov[src_count].data + tmp_offset;
    iov[*iov_len].len = tbuf->iov[src_count].len - tmp_offset;

    if (iov[*iov_len].len >= len)
    {
        iov[*iov_len].len = len;
        *iov_len = 1;
        return;
    }

    len -= iov[*iov_len].len;
    (*iov_len)++;
    src_count++;

    while (len > tbuf->iov[src_count].len)
    {
        len -= tbuf->iov[src_count].len;
        iov[(*iov_len)++] = tbuf->iov[src_count++];
    }

    iov[*iov_len].data = tbuf->iov[src_count].data;
    iov[*iov_len].len = len;
    (*iov_len)++;
}

/****************************** Trim IOVs ************************************/

void
transform_buffer_trim_data_iovs(
        TransformBuffer tbuf,
        TransformIovec iov,
        unsigned int *iov_len)
{
    unsigned int offset = tbuf->data_offset;
    unsigned int tbuf_iov_len = tbuf->iov_len;
    int count;

    *iov_len = 0;

    for (count = 0; count < tbuf->iov_len; count++)
    {
        if (tbuf->iov[count].len > offset)
        {
            break;
        }
        offset -= tbuf->iov[count].len;

        iov[*iov_len] = tbuf->iov[count];
        (*iov_len)++;
    }

    if (count > 0)
    {
        unsigned int data_len = offset + tbuf->data_len;
        unsigned int copy_len = 0;
        int dst_count = 0;

        while (copy_len < data_len)
        {
            copy_len += tbuf->iov[count].len;
            tbuf->iov[dst_count++] = tbuf->iov[count++];
        }

        tbuf->data_offset = offset;
        tbuf->iov_len = dst_count;
        tbuf->total_len = copy_len;
    }
    else
    {
        unsigned int data_len = offset + tbuf->data_len;
        unsigned int copy_len = 0;
        int dst_count = 0;

        while (copy_len < data_len)
        {
            copy_len += tbuf->iov[count].len;
            dst_count++;
            count++;
        }

        tbuf->iov_len = dst_count;
        tbuf->total_len = copy_len;
    }

    for (; count < tbuf_iov_len; count++)
    {
        iov[*iov_len] = tbuf->iov[count];
        (*iov_len)++;
    }
}

/****************************** Adding IOV ***********************************/

void
transform_buffer_add_iov(
        TransformBuffer tbuf,
        unsigned char *data,
        unsigned int len)
{
    ASSERT(tbuf->iov_len < TRANSFORM_BUFFER_MAX_IOV_LEN);

    tbuf->iov[tbuf->iov_len].data = data;
    tbuf->iov[tbuf->iov_len].len = len;

    tbuf->iov_len++;
    tbuf->total_len += len;
}

/******************************* Get IOVs ************************************/

void
transform_buffer_get_iovs(
        TransformBuffer tbuf,
        TransformIovec iov,
        unsigned int *iov_len)
{
    int count;

    for (count = 0; count < tbuf->iov_len; count++)
    {
        iov[count] = tbuf->iov[count];
    }

    *iov_len = tbuf->iov_len;
}

/*********************** Reading data from IOVs ******************************/

static unsigned int
transform_buffer_read_iov(
        TransformIovec iov,
        unsigned int offset,
        unsigned char *data,
        unsigned int len)
{
    unsigned char *src_data;
    unsigned int src_len;

    if (offset == 0)
    {
        src_data = iov->data;
        src_len = iov->len;
    }
    else
    {
        src_data = iov->data + offset;
        src_len = iov->len - offset;
    }

    if (src_len > len)
    {
        src_len = len;
    }

    memcpy(data, src_data, src_len);

    return src_len;
}

static void
transform_buffer_read(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned char *data,
        unsigned int len)
{
    unsigned int iov_num;
    unsigned int tmp_offset;

    if (transform_buffer_locate_iov(
                tbuf->iov,
                tbuf->iov_len,
                offset,
                &iov_num,
                &tmp_offset) == false)
    {
        ASSERT(false);
        return;
    }

    tmp_offset =
      transform_buffer_read_iov(&tbuf->iov[iov_num], tmp_offset, data, len);
    iov_num++;

    while (len > tmp_offset)
    {
        ASSERT(iov_num < tbuf->iov_len);

        tmp_offset += transform_buffer_read_iov(
                              &tbuf->iov[iov_num],
                              0,
                              data + tmp_offset,
                              len - tmp_offset);
        iov_num++;
    }
}

unsigned char *
transform_buffer_get_data(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned char *data_buf,
        unsigned int len)
{
    unsigned char *data = NULL;
    unsigned int iov_num;
    unsigned int tmp_offset;
    bool located;

    if (len == 0)
    {
        return NULL;
    }

    if (offset + len > tbuf->data_len)
    {
        return NULL;
    }

    located =
      transform_buffer_locate_iov(
              tbuf->iov,
              tbuf->iov_len,
              tbuf->data_offset + offset,
              &iov_num,
              &tmp_offset);
    if (located == true)
    {
        /* Check if all data exists in one iov */
        if (len <= tbuf->iov[iov_num].len - tmp_offset)
        {
            data = tbuf->iov[iov_num].data + tmp_offset;
        }
        else
        {
            /* Copy data from transform buffer to data buffer. */
            transform_buffer_read(
                    tbuf,
                    tbuf->data_offset + offset,
                    data_buf,
                    len);
            data = data_buf;
        }
    }

    return data;
}

void
transform_buffer_read_data(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned char *data,
        unsigned int len)
{
    ASSERT(tbuf->data_len >= offset + len);

    /* Read data from transform buffer. */
    transform_buffer_read(tbuf, tbuf->data_offset + offset, data, len);
}


/************************ Writing data to IOVs *******************************/

static unsigned int
transform_buffer_write_iov(
        TransformIovec iov,
        unsigned int offset,
        unsigned char *data,
        unsigned int len)
{
    unsigned char *dst_data;
    unsigned int dst_len;

    if (offset == 0)
    {
        dst_data = iov->data;
        dst_len = iov->len;
    }
    else
    {
        dst_data = iov->data + offset;
        dst_len = iov->len - offset;
    }

    if (dst_len > len)
    {
        dst_len = len;
    }

    memcpy(dst_data, data, dst_len);

    return dst_len;
}

static void
transform_buffer_write(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned char *data,
        unsigned int len)
{
    unsigned int iov_num;
    unsigned int tmp_offset;

    if (len == 0)
    {
        return;
    }

    if (transform_buffer_locate_iov(
                tbuf->iov,
                tbuf->iov_len,
                offset,
                &iov_num,
                &tmp_offset) == false)
    {
        ASSERT(false);
        return;
    }

    tmp_offset =
      transform_buffer_write_iov(&tbuf->iov[iov_num], tmp_offset, data, len);
    iov_num++;

    while (len > tmp_offset)
    {
        ASSERT(iov_num < tbuf->iov_len);

        tmp_offset +=
          transform_buffer_write_iov(
                  &tbuf->iov[iov_num],
                  0,
                  data + tmp_offset,
                  len - tmp_offset);
        iov_num++;
    }
}

void
transform_buffer_add_data(
        TransformBuffer tbuf,
        unsigned char *data,
        unsigned int len)
{
    /* Write data to transform buffer. */
    transform_buffer_write(
            tbuf,
            tbuf->data_offset + tbuf->data_len,
            data,
            len);

    /* Increment data length. */
    tbuf->data_len += len;
}

void
transform_buffer_add_offset_data(
        TransformBuffer tbuf,
        unsigned char *data,
        unsigned int len)
{
    ASSERT(tbuf->data_offset >= len);

    /* Write data to transform buffer. */
    transform_buffer_write(tbuf, tbuf->data_offset - len, data, len);

    /* Increment data length and decrement data offset. */
    tbuf->data_len += len;
    tbuf->data_offset -= len;
}


/************************** Vector iteration *********************************/

bool
transform_buffer_vector_iteration_reset(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned int iteration_len)
{
    unsigned int tmp_offset;
    bool located;
    unsigned int iov_num;

    /* Locate correct iov */
    located =
      transform_buffer_locate_iov(
              tbuf->iov,
              tbuf->iov_len,
              tbuf->data_offset + offset,
              &iov_num,
              &tmp_offset);
    if (located == false)
    {
        tbuf->u.vector_iter.len = 0;
        return false;
    }
    else
    {
        tbuf->u.vector_iter.len = iteration_len;

        tbuf->u.vector_iter.iov_num = iov_num;
        tbuf->u.vector_iter.iov.data = tbuf->iov[iov_num].data + tmp_offset;
        tbuf->u.vector_iter.iov.len = tbuf->iov[iov_num].len - tmp_offset;

        return true;
    }
}

bool
transform_buffer_vector_iteration_next(
        TransformBuffer tbuf,
        unsigned char **vector,
        unsigned int *len)
{
    /* Check if iteration is completed. */
    if (tbuf->u.vector_iter.len == 0)
    {
        return false;
    }

    /* Check if all remaining data exist in one iov */
    if (tbuf->u.vector_iter.len <= tbuf->u.vector_iter.iov.len)
    {
        *vector = tbuf->u.vector_iter.iov.data;
        *len = tbuf->u.vector_iter.len;
    }
    else
    {
        *vector = tbuf->u.vector_iter.iov.data;
        *len = tbuf->u.vector_iter.iov.len;

        tbuf->u.vector_iter.iov_num++;
        tbuf->u.vector_iter.iov = tbuf->iov[tbuf->u.vector_iter.iov_num];
    }

    tbuf->u.vector_iter.len -= *len;

    return true;
}

/*************************** Block iteration *********************************/

bool
transform_buffer_block_iteration_reset(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned int iteration_len,
        unsigned int block_size,
        unsigned char *block_buf,
        bool do_copy)
{
    unsigned int start_offset = tbuf->data_offset + offset;
    unsigned int tmp_offset;
    unsigned int iov_num;
    bool located;

   /* Check that transform buffer contains enough space */
    if (tbuf->total_len < (start_offset + iteration_len))
    {
        tbuf->u.block_iter.len = 0;
        return false;
    }

    /* Locate correct iov */
    located =
      transform_buffer_locate_iov(
              tbuf->iov,
              tbuf->iov_len,
              start_offset,
              &iov_num,
              &tmp_offset);
    if (located == false)
    {
        tbuf->u.block_iter.len = 0;
        return false;
    }

    /* Set generic iteration variables */
    tbuf->u.block_iter.len = iteration_len;
    tbuf->u.block_iter.iov_num = iov_num;
    tbuf->u.block_iter.iov.data = tbuf->iov[iov_num].data + tmp_offset;
    tbuf->u.block_iter.iov.len = tbuf->iov[iov_num].len - tmp_offset;

    /* Set variables specific for block iteration */
    tbuf->u.block_iter.offset = start_offset;
    tbuf->u.block_iter.buf = block_buf;
    tbuf->u.block_iter.size = block_size;
    tbuf->u.block_iter.write_offset = 0;
    tbuf->u.block_iter.write_len = 0;
    tbuf->u.block_iter.do_copy = do_copy;

    return true;
}

bool
transform_buffer_block_iteration_next(
        TransformBuffer tbuf,
        unsigned char **block,
        unsigned int *len)
{
    unsigned int tmp_len;

    /* Check if iteration is completed. */
    if (tbuf->u.block_iter.len == 0)
    {
        return false;
    }

    /* Check if all remaining data exist in one iov */
    if (tbuf->u.block_iter.len <= tbuf->u.block_iter.iov.len)
    {
        /* Calculate block length */
        tmp_len = tbuf->u.block_iter.len & ~(tbuf->u.block_iter.size - 1);

        /* Just set return variables if all data handled from iov.
           Otherwise adjust iteration variables of current iov too. */
        if ((tmp_len == tbuf->u.block_iter.len) || (tmp_len == 0))
        {
            *block = tbuf->u.block_iter.iov.data;
            *len = tbuf->u.block_iter.len;
        }
        else
        {
            *block = tbuf->u.block_iter.iov.data;
            *len = tmp_len;

            tbuf->u.block_iter.iov.data += tmp_len;
            tbuf->u.block_iter.iov.len -= tmp_len;
        }
    }
    /* Check if iov contains at least one block of data */
    else if (tbuf->u.block_iter.iov.len >= tbuf->u.block_iter.size)
    {
        /* Calculate block length and set return variables. */
        tmp_len = tbuf->u.block_iter.iov.len & ~(tbuf->u.block_iter.size - 1);

        *block = tbuf->u.block_iter.iov.data;
        *len = tmp_len;

        /* Get next iov if all data is iterated through from this iov.
           Otherwise adjust iteration variables of current iov. */
        if (tmp_len == tbuf->u.block_iter.iov.len)
        {
            tbuf->u.block_iter.iov_num++;
            tbuf->u.block_iter.iov = tbuf->iov[tbuf->u.block_iter.iov_num];
        }
        else
        {
            tbuf->u.block_iter.iov.data += tmp_len;
            tbuf->u.block_iter.iov.len -= tmp_len;
        }
    }
    /* Other cases iov contains only partial block. */
    else
    {
        /* Return remaining iteration length if it is smaller or equal than
           block size. Otherwise return whole block and calculate iteration
           iov variables. */
        if (tbuf->u.block_iter.len <= tbuf->u.block_iter.size)
        {
            *block = tbuf->u.block_iter.buf;
            *len = tbuf->u.block_iter.len;
        }
        else
        {
            unsigned int tmp_offset;
            unsigned int src_count;

            *block = tbuf->u.block_iter.buf;
            *len = tbuf->u.block_iter.size;

            tmp_len = tbuf->u.block_iter.size - tbuf->u.block_iter.iov.len;

            tbuf->u.block_iter.iov_num++;

            /* Locate correct source iov */
            if (transform_buffer_locate_iov(
                        &tbuf->iov[tbuf->u.block_iter.iov_num],
                        tbuf->iov_len - tbuf->u.block_iter.iov_num,
                        tmp_len,
                        &src_count,
                        &tmp_offset) == false)
            {
                ASSERT(false);
                return false;
            }

            tbuf->u.block_iter.iov_num += src_count;
            tbuf->u.block_iter.iov.data =
              tbuf->iov[tbuf->u.block_iter.iov_num].data + tmp_offset;
            tbuf->u.block_iter.iov.len =
              tbuf->iov[tbuf->u.block_iter.iov_num].len - tmp_offset;
        }

        /* Copy check */
        if (tbuf->u.block_iter.do_copy == true)
        {
            /* Copy data from transform buffer to iteration buffer. */
            transform_buffer_read(
                    tbuf,
                    tbuf->u.block_iter.offset,
                    tbuf->u.block_iter.buf,
                    *len);
        }
        else
        {
            /* Set variables used in transform_buffer_write_block()
               function if user wants to write data from iteration
               buffer to transform buffer later. */
            tbuf->u.block_iter.write_offset = tbuf->u.block_iter.offset;
            tbuf->u.block_iter.write_len = *len;
        }
    }

    tbuf->u.block_iter.offset += *len;
    tbuf->u.block_iter.len -= *len;

    return true;
}

void
transform_buffer_block_iteration_write(
        TransformBuffer tbuf)
{
    if (tbuf->u.block_iter.write_len > 0)
    {
        transform_buffer_write(
                tbuf,
                tbuf->u.block_iter.write_offset,
                tbuf->u.block_iter.buf,
                tbuf->u.block_iter.write_len);

        tbuf->u.block_iter.write_len = 0;
    }
}

/*************************** Block iteration *********************************/

bool
transform_buffer_data_iteration_reset(
        TransformBuffer tbuf,
        unsigned int offset,
        unsigned int iteration_len)
{
    unsigned int tmp_offset;
    bool located;
    unsigned int iov_num;

    /* Check that transform buffer contains enough data. */
    if ((offset >= tbuf->data_len) ||
        (iteration_len > (tbuf->data_len - offset)))
    {
        tbuf->u.data_iter.len = 0;
        return false;
    }

    /* Locate correct iov */
    located =
      transform_buffer_locate_iov(
              tbuf->iov,
              tbuf->iov_len,
              tbuf->data_offset + offset,
              &iov_num,
              &tmp_offset);
    if (located == false)
    {
        tbuf->u.data_iter.len = 0;
        return false;
    }
    else
    {
        tbuf->u.data_iter.len = iteration_len;

        tbuf->u.data_iter.iov_num = iov_num;
        tbuf->u.data_iter.iov.data = tbuf->iov[iov_num].data + tmp_offset;
        tbuf->u.data_iter.iov.len = tbuf->iov[iov_num].len - tmp_offset;

        tbuf->u.data_iter.offset = tbuf->data_offset + offset;

        return true;
    }
}

unsigned char *
transform_buffer_data_iteration_next(
        TransformBuffer tbuf,
        unsigned char *data,
        unsigned int len)
{
    /* Check that there is enough data what to iterate. */
    if (tbuf->u.data_iter.len < len)
    {
        return NULL;
    }

    /* Check if all data exists in one iov */
    if (len <= tbuf->u.data_iter.iov.len)
    {
        data = tbuf->u.data_iter.iov.data;

        /* Get next iov if all data is iterated through from this iov.
           Otherwise adjust iteration variables of current iov. */
        if (len == tbuf->u.data_iter.iov.len)
        {
            tbuf->u.data_iter.iov_num++;
            tbuf->u.data_iter.iov = tbuf->iov[tbuf->u.data_iter.iov_num];
        }
        else
        {
            tbuf->u.data_iter.iov.data += len;
            tbuf->u.data_iter.iov.len -= len;
        }
    }
    else
    {
        /* IOV variable are only update if there is still data to iterate. */
        if (tbuf->u.data_iter.len > len)
        {
            unsigned int tmp_offset;
            unsigned int src_count;

            tbuf->u.data_iter.iov_num++;

            /* Locate correct source iov */
            if (transform_buffer_locate_iov(
                        &tbuf->iov[tbuf->u.data_iter.iov_num],
                        tbuf->iov_len - tbuf->u.data_iter.iov_num,
                        len - tbuf->u.data_iter.iov.len,
                        &src_count,
                        &tmp_offset) == false)
            {
                ASSERT(false);
                return NULL;
            }

            tbuf->u.data_iter.iov_num += src_count;
            tbuf->u.data_iter.iov.data =
              tbuf->iov[tbuf->u.data_iter.iov_num].data + tmp_offset;
            tbuf->u.data_iter.iov.len =
              tbuf->iov[tbuf->u.data_iter.iov_num].len - tmp_offset;
        }

        /* Copy data from transform buffer to data buffer. */
        transform_buffer_read(
                tbuf,
                tbuf->u.data_iter.offset,
                data,
                len);
    }

    tbuf->u.data_iter.offset += len;
    tbuf->u.data_iter.len -= len;

    return data;
}

bool
transform_buffer_data_iteration_inc(
        TransformBuffer tbuf,
        unsigned int len)
{
    /* Check that there is enough data what to iterate. */
    if (tbuf->u.data_iter.len < len)
    {
        return false;
    }

    if (len > 0)
    {
        unsigned int iov_num;
        unsigned int tmp_offset;

        if (transform_buffer_locate_iov(
                    tbuf->iov,
                    tbuf->iov_len,
                    tbuf->u.data_iter.offset + len,
                    &iov_num,
                    &tmp_offset) == false)
        {
            ASSERT(false);
            return false;
        }

        tbuf->u.data_iter.iov_num = iov_num;
        tbuf->u.data_iter.iov.data = tbuf->iov[iov_num].data + tmp_offset;
        tbuf->u.data_iter.iov.len = tbuf->iov[iov_num].len - tmp_offset;

        tbuf->u.data_iter.offset += len;
        tbuf->u.data_iter.len -= len;
    }

    return true;
}

bool
transform_buffer_data_iteration_dec(
        TransformBuffer tbuf,
        unsigned int len)
{
    /* Check that there is enough data what to decrement. */
    if (tbuf->u.data_iter.offset < len)
    {
        return false;
    }

    if (len > 0)
    {
        unsigned int iov_num;
        unsigned int tmp_offset;

        if (transform_buffer_locate_iov(
                    tbuf->iov,
                    tbuf->iov_len,
                    tbuf->u.data_iter.offset - len,
                    &iov_num,
                    &tmp_offset) == false)
        {
            ASSERT(false);
            return false;
        }

        tbuf->u.data_iter.iov_num = iov_num;
        tbuf->u.data_iter.iov.data = tbuf->iov[iov_num].data + tmp_offset;
        tbuf->u.data_iter.iov.len = tbuf->iov[iov_num].len - tmp_offset;

        tbuf->u.data_iter.offset -= len;
        tbuf->u.data_iter.len += len;
    }

    return true;
}


void
transform_buffer_copy(
        TransformBuffer tbuf_dst,
        TransformBuffer tbuf_src,
        unsigned int offset_src,
        unsigned int len)
{
    unsigned char *vector;
    unsigned int vector_len;

    bool ok;

    ok =
        transform_buffer_vector_iteration_reset(
                tbuf_src,
                offset_src,
                len);

    if (ok == true)
    {
        while (transform_buffer_vector_iteration_next(
                       tbuf_src,
                       &vector,
                       &vector_len)
               == true)
        {
            transform_buffer_add_data(tbuf_dst, vector, vector_len);
        }
    }

    ASSERT(ok == true);
}
