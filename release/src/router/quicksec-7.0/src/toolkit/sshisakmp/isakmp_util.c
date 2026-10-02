/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp library utility functions.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_util.h"
#include "sshdebug.h"
#include "sshbuffer.h"

#define SSH_DEBUG_MODULE "SshIkeUtil"

struct SshIkeSAAttributeListRec {
  uint32_t number_of_attributes;
  uint32_t number_of_allocated_entries;
  SshIkeDataAttribute data_attributes;
  SshBuffer buffer;
  bool error;
};

/* Allocate SA data attribute list. This list can be used to create
   sa_attributes entry in the SshIkePayloadT structure. Allocate new list using
   this function, and then add entries to it by calling
   ssh_ike_data_attribute_list_add* functions. After all attributes has been
   added call function ssh_ike_data_attribute_list_get to get the final list
   out (which can be freed by just simple ssh_free, it will free both data
   structure, and the data). Then free the list itself by calling
   ssh_ike_data_attribute_list_free. */
SshIkeSAAttributeList ssh_ike_data_attribute_list_allocate(void)
{
    SshIkeSAAttributeList list;
    list = ssh_calloc(1, sizeof(struct SshIkeSAAttributeListRec));
    if (list == NULL)
      return NULL;
    list->number_of_allocated_entries = 10;
    list->data_attributes = ssh_calloc(list->number_of_allocated_entries,
                                       sizeof(struct SshIkeDataAttributeRec));
    if (list->data_attributes == NULL)
    {
        ssh_free(list);
        return NULL;
    }
    list->buffer = ssh_buffer_allocate();
    if (list->buffer == NULL)
    {
        ssh_free(list->data_attributes);
        ssh_free(list);
        return NULL;
    }
    return list;
}

/* Add buffer entry to the SA data attribute list. This copies the data to the
   list. */
void ssh_ike_data_attribute_list_add(SshIkeSAAttributeList list,
                                     uint16_t type,
                                     unsigned char *buffer,
                                     size_t length)
{
    SshIkeDataAttribute attr;

    if (list->error)
      return;

    if (list->number_of_attributes == list->number_of_allocated_entries)
    {
        if (!ssh_recalloc(&list->data_attributes,
                          &list->number_of_allocated_entries,
                          list->number_of_allocated_entries + 10,
                          sizeof(struct SshIkeDataAttributeRec)))
        {
            list->error = true;
            return;
        }
    }
    attr = &(list->data_attributes[list->number_of_attributes]);
    list->number_of_attributes++;
    attr->attribute_type = type;
    attr->attribute_length = length;
    attr->attribute = (unsigned char *) ssh_buffer_len(list->buffer);
    if (ssh_buffer_append(list->buffer, buffer, length) != SSH_BUFFER_OK)
      list->error = true;
    return;
}

/* Add basic integer (16 bit) to the SA data attribute list */
void ssh_ike_data_attribute_list_add_basic(SshIkeSAAttributeList list,
                                           uint16_t type,
                                           uint16_t number)
{
    unsigned char buf[2];

    SSH_PUT_16BIT(buf, number);
    ssh_ike_data_attribute_list_add(list, type, buf, 2);
}

/* Add integer to the SA data attribute list */
void ssh_ike_data_attribute_list_add_int(SshIkeSAAttributeList list,
                                         uint16_t type,
                                         uint64_t number)
{
    unsigned char buf[8];
    uint16_t uint16;
    uint32_t uint32;

    if ((number >> 16) == 0)
    {
        uint16 = (uint16_t) number;
        SSH_PUT_16BIT(buf, uint16);
        ssh_ike_data_attribute_list_add(list, type, buf, 2);
    }
    else if (number == (number & 0xFFFFFFFF))
    {
        uint32 = (uint32_t) number;
        SSH_PUT_32BIT(buf, uint32);
        ssh_ike_data_attribute_list_add(list, type, buf, 4);
    }
    else
    {
        SSH_PUT_64BIT(buf, number);
        ssh_ike_data_attribute_list_add(list, type, buf, 8);
    }
}

/* Add mp integer to the SA data attribute list */
void ssh_ike_data_attribute_list_add_mpint(SshIkeSAAttributeList list,
                                           uint16_t type,
                                           SshMPInteger number)
{
    size_t len;
    unsigned char *buf;

    /* Get size */
    len = ssh_mprz_byte_size(number);

    /* Allocate buffer, and store number there */
    buf = ssh_malloc(len);
    if (buf == NULL)
    {
        list->error = true;
        return;
    }
    ssh_mprz_get_buf(buf, len, number);

    /* Add mp integer to the list */
    ssh_ike_data_attribute_list_add(list, type, buf, len);

    /* Free temporary buffer */
    ssh_free(buf);
}

/* Get SA data attribute data structure out from the SA data attribute list */
SshIkeDataAttribute ssh_ike_data_attribute_list_get(SshIkeSAAttributeList list,
                                                    int *number_of_attributes)
{
    size_t total_size;
    int i;
    unsigned char *start;
    SshIkeDataAttribute data;

    if (list->error)
    {
        return NULL;
    }

    /* Calculate total size */
    total_size = list->number_of_attributes *
      sizeof(struct SshIkeDataAttributeRec) + ssh_buffer_len(list->buffer);

    /* Allocate buffer to store attributes and data */
    data = ssh_malloc(total_size);
    if (data == NULL)
      return NULL;
    memcpy(data, list->data_attributes, list->number_of_attributes *
           sizeof(struct SshIkeDataAttributeRec));

    /* Copy the data in */
    start = (unsigned char *) &(data[list->number_of_attributes]);
    memcpy(start, ssh_buffer_ptr(list->buffer), ssh_buffer_len(list->buffer));

    /* Update the attribute pointers to point correct place */
    for (i = 0; i < list->number_of_attributes; i++)
      data[i].attribute = (unsigned long) data[i].attribute + start;
    *number_of_attributes = list->number_of_attributes;
    return data;
}

/* Free SA data attribute list */
void ssh_ike_data_attribute_list_free(SshIkeSAAttributeList list)
{
    ssh_free(list->data_attributes);
    ssh_buffer_free(list->buffer);
    /* Free old list */
    list->number_of_allocated_entries = 0;
    ssh_free(list);
}


char *ike_ip_string(SshIpAddr ip,
                    char *space, size_t space_size)
{
    ssh_snprintf(space, space_size, "%@", ssh_ipaddr_render, ip);
    return space;
}

char *ike_port_string(uint16_t port,
                      char *space, size_t space_size)
{
    ssh_snprintf(space, space_size, "%d", port);
    return space;
}


const char *isakmp_name_or_unknown(const char *name)
{
    if (name == NULL)
    {
        name = "unknown";
    }

    return name;
}
