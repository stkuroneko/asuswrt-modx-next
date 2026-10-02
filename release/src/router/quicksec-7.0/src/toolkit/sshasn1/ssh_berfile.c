/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "ssh_berfile.h"

#define SSH_DEBUG_MODULE "SshAsn1BerFile"

#ifdef SSHDIST_ASN1

struct SshBERFileRec {
  /* Contains the data of all records. */
  unsigned char *data;
  /* Length of the data. */
  size_t data_len;
  /* Number of records */
  uint32_t num_records;
  /* Records */
  SshBERFileRecord *records;
  /* Enumeration position. */
  uint32_t enum_index;
};

struct SshBERFileRecordRec {
  /* File into which this record belongs. */
  SshBERFile file;
  /* Offset in the file. */
  size_t offset;
  /* Length including header. */
  size_t length;
};

static bool
read_ber_header(const unsigned char *data,
                size_t data_len,
                uint32_t *header_len,
                unsigned char *identifier_ret,
                uint32_t *tag_ret,
                uint32_t *len_ret)
{
#define ADVANCE if (++ofs >= data_len) return false

    int ofs = 0;

    if (data_len < 2)
      return false;

    *identifier_ret = data[ofs];
    *tag_ret = data[ofs] & 0x1F;

    /* Check if TAG is greater than 30. */
    if (*tag_ret == 0x1F)
    {
        /* Reset the tag. */
        *tag_ret = 0;

        /* Pass the identifier octet. */
        ofs++;
        SSH_ASSERT(ofs < data_len);

        /* Calculate TAG. */
        while (data[ofs] & 0x80)
        {
            *tag_ret = ((*tag_ret << 7) | (data[ofs] & 0x7F));
            ADVANCE;
        }
    }
    else
    {
        /* Pass the identifier octet. */
        ofs++;
        SSH_ASSERT(ofs < data_len);
    }

    /* Check if length is encoded with long format. */
    if (data[ofs] & 0x80)
    {
        int num_octets;

        *len_ret = 0;
        num_octets = data[ofs] & 0x7F;
        while (num_octets--)
        {
            ADVANCE;
            *len_ret = ((*len_ret << 8) | data[ofs]);
        }
        ADVANCE; /* pass the last length octet */
    }
    else
    {
        *len_ret = data[ofs] & 0x7F;
        ADVANCE;
    }
    *header_len = ofs;
    return true;

#undef ADVANCE
}

static bool
increase_record_array_size(SshBERFile file)
{
    void *tmp;

    if ((tmp =
         ssh_realloc(file->records,
                     (file->num_records    * sizeof(SshBERFileRecord)),
                     (file->num_records+1) * sizeof(SshBERFileRecord)))
        == NULL)
      return false;

    file->records = tmp;
    return true;
}

#define EMPTY_HEADER_SIZE 4

/* Size must include the 4 byte header. */
static void
set_empty_ber(unsigned char *data,
              size_t size,
              bool clear)
{
    /* Ignore too small buffers */
    if (size < EMPTY_HEADER_SIZE)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Too small BER-encoded buffer"));
        return;
    }

    data[0] = 0x00;
    data[1] = 0x82;
    data[2] = (((size - EMPTY_HEADER_SIZE) & 0x0000FF00) >> 8L);
    data[3] = ((size - EMPTY_HEADER_SIZE)& 0x000000FF);
    if (clear) memset(data + EMPTY_HEADER_SIZE, 0, size - EMPTY_HEADER_SIZE);
}

/* Length must be the BER data length, including the header size */
static void
set_record_empty(SshBERFileRecord rec, size_t length)
{
    rec->length = length;

    set_empty_ber(rec->file->data + rec->offset,
                  rec->length,
                  true);
}

static bool
is_empty_record(SshBERFileRecord record)
{
    return (*(record->file->data + record->offset) == 0);
}

static void
free_records(SshBERFileRecord *records, uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++)
      ssh_free(records[i]);
}

static SshBERFileStatus
read_records(SshBERFile file,
             const unsigned char *data,
             size_t data_len)
{
    SshBERFileStatus r = SSH_BER_FILE_ERR_OK;
    size_t ofs = 0, real_len;
    uint32_t header_len, ber_tag, ber_len;
    unsigned char ber_identifier;
    SshBERFileRecord rec;

    real_len = data_len;

    /* Hack for handling 0xFF padded BER files. */
    /* #21131: Added check for remaining data length to avoid underflow */
    if (data_len > 2 &&
        data[data_len-1] == 0xFF && data[data_len-2] == 0xFF)
    {
        while (data_len > 0 && data[--data_len] == 0xFF) ;
    }

    if (data_len == 0)
    {
        return SSH_BER_FILE_ERR_MEMORY;
    }

    file->data_len = real_len;
    file->data = ssh_memdup(data, file->data_len);

    if (file->data == NULL)
    {
        return SSH_BER_FILE_ERR_MEMORY;
    }

    while (ofs < data_len)
    {
        if (!read_ber_header(data + ofs,
                             data_len - ofs,
                             &header_len,
                             &ber_identifier,
                             &ber_tag,
                             &ber_len))
        {
            r = SSH_BER_FILE_ERR_FORMAT;
            goto cleanup;
        }

        if ((rec = ssh_calloc(1, sizeof(*rec))) == NULL)
        {
            r = SSH_BER_FILE_ERR_MEMORY;
            goto cleanup;
        }

        if (!increase_record_array_size(file))
        {
            r = SSH_BER_FILE_ERR_MEMORY;
            ssh_free(rec);
            goto cleanup;
        }

        file->records[file->num_records] = rec;
        file->num_records++;

        rec->file = file;
        rec->offset = ofs;
        if (ber_identifier == 0 && ber_len == 0)
        {
            rec->length = real_len - ofs;
            set_record_empty(rec, rec->length);
            break;
        }
        else
        {
            rec->length = header_len + ber_len;
        }
        ofs += (header_len + ber_len);
    }
  cleanup:
    if (r != SSH_BER_FILE_ERR_OK)
    {
        free_records(file->records, file->num_records);
        ssh_free(file->data);
        file->data = NULL;
        file->num_records = 0;
    }
    return r;
}

SshBERFileStatus
ssh_ber_file_create(const unsigned char *data,
                    size_t data_len,
                    SshBERFile *file_ret)
{
    SshBERFileStatus r = SSH_BER_FILE_ERR_OK;
    SshBERFile file;


    if ((file = ssh_calloc(1, sizeof(*file))) == NULL)
      return SSH_BER_FILE_ERR_MEMORY;

    if (data)
    {
        r = read_records(file, data, data_len);
        if (r != SSH_BER_FILE_ERR_OK)
        {
            ssh_ber_file_destroy(file);
            return r;
        }
    }
    else if (data_len > 0)
    {
        file->num_records = 1;
        file->records[0] = ssh_calloc(1, sizeof(struct SshBERFileRecordRec));
        if (!file->records[0])
        {
            ssh_ber_file_destroy(file);
            return SSH_BER_FILE_ERR_MEMORY;
        }
        file->records[0]->file = file;
        file->records[0]->offset = 0;
        file->records[0]->length = data_len;
        set_empty_ber(file->data, data_len, false);
    }
    *file_ret = file;
    return r;
}

void
ssh_ber_file_destroy(SshBERFile file)
{
    free_records(file->records, file->num_records);
    ssh_free(file->records);
    ssh_free(file->data);
    ssh_free(file);
}


SshBERFileStatus
ssh_ber_file_resize(SshBERFile file,
                    int32_t delta)
{
    unsigned char *tmp;

    if (delta < 0)
    {
        /* There has to be free space record from which to cut
           the space. */
        if (-delta + EMPTY_HEADER_SIZE > ssh_ber_file_get_free_space(file))
          return SSH_BER_FILE_ERR_NO_SPACE;
    }
    tmp = ssh_realloc(file->data, 0, file->data_len + delta);
    if (tmp == NULL)
      return SSH_BER_FILE_ERR_MEMORY;

    file->data = tmp;
    file->data_len += delta;
    set_record_empty(file->records[file->num_records-1],
                     file->records[file->num_records-1]->length + delta);
    return SSH_BER_FILE_ERR_OK;
}

SshBERFileStatus
ssh_ber_file_compress(SshBERFile file)
{
    SshBERFileRecord free_rec;
    uint32_t delta, i, j;

    if (file->num_records == 0)
      return SSH_BER_FILE_ERR_OK;

    for (i = 0; i + 1 < file->num_records; i++)
      if (is_empty_record(file->records[i]))
      {
          delta = file->records[i]->length;
          for (j = i; j < file->num_records; j++)
          {
              file->records[j] = file->records[j+1];
              file->records[j]->offset -= delta;
          }
          file->num_records--;
      }
    free_rec = file->records[file->num_records-1];

    set_record_empty(free_rec,
                     file->data_len - free_rec->offset);

    return SSH_BER_FILE_ERR_OK;
}

uint32_t
ssh_ber_file_get_free_space(SshBERFile file)
{
    if (file->num_records == 0 ||
        !is_empty_record(file->records[file->num_records-1])) return 0;
    return file->records[file->num_records-1]->length;
}

void
ssh_ber_file_get_data(SshBERFile file,
                      unsigned char **data_ret,
                      size_t *data_len_ret)
{
    *data_ret = file->data;
    *data_len_ret = file->data_len;
}

SshBERFileStatus
ssh_ber_file_add_record(SshBERFile file,
                        const unsigned char *data,
                        size_t data_len,
                        SshBERFileRecord *record_ret)
{
    SshBERFileRecord rec, free_rec;

    if (data_len > ssh_ber_file_get_free_space(file))
      return SSH_BER_FILE_ERR_NO_SPACE;

    /* Get pointer to last record. */
    free_rec = file->records[file->num_records-1];

    /* Allocated new record */
    if ((rec = ssh_calloc(1, sizeof(*rec))) == NULL)
      return SSH_BER_FILE_ERR_MEMORY;

    /* Reallocate record pointer array. */
    if (!increase_record_array_size(file))
    {
        ssh_free(rec);
        return SSH_BER_FILE_ERR_MEMORY;
    }

    /* Set attributes of new record. It's offset will be set
       to the offset of the free record. */
    rec->file = file;
    rec->offset = free_rec->offset;
    rec->length = data_len;

    /* Copy the data. */
    memcpy(file->data + rec->offset, data, data_len);

    /* Insert record pointer before the free record. */
    file->records[file->num_records] = file->records[file->num_records-1];
    file->records[file->num_records-1] = rec;
    /* Adjust free record offset. */
    free_rec->offset += data_len;
    /* Reset free record BER data. */
    set_record_empty(free_rec, file->data_len - free_rec->offset);
    /* increase record count. */
    file->num_records++;
    if (record_ret)
      *record_ret = rec;
    return SSH_BER_FILE_ERR_OK;
}

void
ssh_ber_file_enum_start(SshBERFile file)
{
    file->enum_index = 0;
}

bool
ssh_ber_file_enum_next(SshBERFile file,
                       SshBERFileRecord *record_ret)
{
    SshBERFileRecord rec;

  again:
    if (file->enum_index >= file->num_records)
      return false;
    rec = file->records[file->enum_index];
    file->enum_index++;

    if (is_empty_record(rec)) goto again;
    *record_ret = rec;
    return true;
}

void
ssh_ber_record_destroy(SshBERFileRecord record)
{
    set_record_empty(record, record->length);
}

void
ssh_ber_record_get_data(SshBERFileRecord record,
                        unsigned char **data_ret,
                        size_t *data_len_ret)
{
    *data_ret = record->file->data + record->offset;
    *data_len_ret = record->length;
}

static void
fix_offsets(SshBERFile file, uint32_t offset, int32_t delta)
{
    uint32_t i;

    for (i = 0; i < file->num_records; i++)
      if (file->records[i]->offset > offset)
        file->records[i]->offset += delta;
}

SshBERFileStatus
ssh_ber_record_set_data(SshBERFileRecord record,
                        const unsigned char *data,
                        size_t data_len)
{
    int32_t delta;
    SshBERFileRecord free_rec;

    free_rec = record->file->records[record->file->num_records-1];
    delta = data_len - record->length;

    /* Check the available space. */
    if (delta > 0 && ssh_ber_file_get_free_space(record->file) < delta)
      return SSH_BER_FILE_ERR_NO_SPACE;

    if (delta != 0)
    {
        /* Move file data. */
        memmove(record->file->data + record->offset + record->length + delta,
                record->file->data + record->offset + record->length,
                record->file->data_len - record->offset - record->length);

        record->length+=delta;
    }
    memcpy(record->file->data + record->offset, data, data_len);

    /* Fix the offsets */
    fix_offsets(record->file, record->offset, delta);

    /* Update the last record length */
    set_record_empty(free_rec, free_rec->file->data_len - free_rec->offset);

    return SSH_BER_FILE_ERR_OK;
}
#endif /* SSHDIST_ASN1 */
