/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Conf payload utility functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2ConfUtil"

/* Duplicate Configuration payload. This will take new entry from the
   free list and copy data from the current Configuration data in to
   it. This will return NULL if no free Configuration payloads
   available. */
SshIkev2PayloadConf
ssh_ikev2_conf_dup(SshSADHandle sad_handle,
                   SshIkev2PayloadConf conf)
{
  SshIkev2PayloadConf conf_copy;

  conf_copy = ssh_ikev2_conf_allocate(sad_handle, conf->conf_type);
  if (conf_copy == NULL)
    return NULL;

  /* Copy items. */
  if (conf->number_of_conf_attributes_used >
      conf_copy->number_of_conf_attributes_allocated)
    {
      conf_copy->conf_attributes =
        ssh_realloc(conf_copy->conf_attributes,
                    conf_copy->number_of_conf_attributes_allocated *
                    sizeof(*(conf_copy->conf_attributes)),
                    conf->number_of_conf_attributes_used *
                    sizeof(*(conf_copy->conf_attributes)));
      if (conf_copy->conf_attributes == NULL)
        {
          conf_copy->number_of_conf_attributes_allocated = 0;
          return NULL;
        }
      conf_copy->number_of_conf_attributes_allocated =
        conf->number_of_conf_attributes_used;
    }
  memcpy(conf_copy->conf_attributes, conf->conf_attributes,
         conf->number_of_conf_attributes_used *
         sizeof(*(conf->conf_attributes)));
  conf_copy->number_of_conf_attributes_used =
    conf->number_of_conf_attributes_used;
  return conf_copy;
}

/* Take extra reference to the configuration payload. */
void
ssh_ikev2_conf_take_ref(SshSADHandle sad_handle,
                        SshIkev2PayloadConf conf)
{
  conf->ref_cnt++;
}

/* Add attribute to the configuration payload. This will add
   new entry to the end of the list. */
SshIkev2Error
ssh_ikev2_conf_add(SshIkev2PayloadConf conf,
                   SshIkev2ConfAttributeType attribute_type,
                   size_t length,
                   const unsigned char *value)
{
  SshIkev2ConfAttribute attribute;
  if (conf->number_of_conf_attributes_used >=
      conf->number_of_conf_attributes_allocated)
    {



      if (!ssh_recalloc(&(conf->conf_attributes),
                        &(conf->number_of_conf_attributes_allocated),
                        conf->number_of_conf_attributes_allocated +
                        SSH_IKEV2_CONF_ATTRIBUTES_ADD,
                        sizeof(*(conf->conf_attributes))))
        {
          return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
    }
  attribute = &(conf->conf_attributes[conf->number_of_conf_attributes_used]);
  attribute->attribute_type = attribute_type;
  attribute->length = length;
  if (attribute->length > SSH_IKEV2_CONF_ATTRIBUTE_MAX_SIZE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ssh_ikev2_conf_add gets value whose length "
                             "is more than %d bytes, truncated",
                             SSH_IKEV2_CONF_ATTRIBUTE_MAX_SIZE));
      attribute->length = SSH_IKEV2_CONF_ATTRIBUTE_MAX_SIZE;
    }
  memcpy(attribute->value, value, attribute->length);
  conf->number_of_conf_attributes_used++;
  return SSH_IKEV2_ERROR_OK;
}

