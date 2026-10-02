/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel-mode virtual adapter interface.
*/

#ifndef VIRTUAL_ADAPTER_H
#define VIRTUAL_ADAPTER_H

#include "ip_interfaces.h"

/* XXX virtual_adapter.h */
/** Virtual adapter state. */
typedef enum {
  /** Invalid value */
  SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED        = 0,
  /** Up */
  SSH_VIRTUAL_ADAPTER_STATE_UP               = 1,
  /** Down */
  SSH_VIRTUAL_ADAPTER_STATE_DOWN             = 2,
  /** Keep existing state */
  SSH_VIRTUAL_ADAPTER_STATE_KEEP_OLD         = 3,
} SshVirtualAdapterState;


typedef enum {
  /** Success */
  SSH_VIRTUAL_ADAPTER_ERROR_OK              = 0,
  /** Success, status callback will be called again */
  SSH_VIRTUAL_ADAPTER_ERROR_OK_MORE         = 1,
  /** Nonexistent adapter */
  SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT     = 2,
  /** Address configuration error */
  SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE = 3,
  /** Route configuration error */
  SSH_VIRTUAL_ADAPTER_ERROR_ROUTE_FAILURE   = 4,
  /** Parameter configuration error */
  SSH_VIRTUAL_ADAPTER_ERROR_PARAM_FAILURE   = 5,
  /** Memory allocation error */
  SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY   = 6,
  /** Undefined internal error */
  SSH_VIRTUAL_ADAPTER_ERROR_UNKNOWN_ERROR   = 255
} SshVirtualAdapterError;

/** Optional parameters for a virtual adapter. */
struct SshVirtualAdapterParamsRec
{
    /** Virtual adapter mtu. */
    uint32_t mtu;

    /** DNS server IP addresses. */
    uint32_t dns_ip_count;
    SshIpAddr dns_ip;

    /** WINS server IP addresses. */
    uint32_t wins_ip_count;
    SshIpAddr wins_ip;

    /** Windows domain name. */
    char *win_domain;

    /** Netbios node type. */
    uint8_t netbios_node_type;

    /** Routing instance id */
    SshVriId routing_instance_id;
};

typedef struct SshVirtualAdapterParamsRec SshVirtualAdapterParamsStruct;
typedef struct SshVirtualAdapterParamsRec *SshVirtualAdapterParams;

#endif /* not VIRTUAL_ADAPTER_H */
