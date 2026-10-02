/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   XML configuration for QuickSec policy manager.
*/

#ifndef SSHQUICKSECPM_XMLCONF_H
#define SSHQUICKSECPM_XMLCONF_H

#include "ipsec_params.h"

#include "quicksec_pm.h"
#include "common_xmlconf.h"

/*************************** Types and definitions ***************************/

/** Static configuration parameters for the policy manager.  These are
   specified from the command line. */
struct SshIpmParamsRec
{
    /** The name of the policy manager executable. */
    const char *program;
    char hostname[256];               /** Hostname. */
    const char *config_file;          /** -f */
    char *debug_level;                /** -D */
    bool print_interface_info;              /** -i */
    bool no_dns_pass_rule;
    bool disable_dhcp_client_pass_rule;
    bool enable_dhcp_server_pass_rule;
    const char *appgw_addr;           /** -B */
    char *ike_addr;                   /** -b */
    uint16_t num_ike_ports;
    uint16_t local_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];      /** --ike-ports */
    uint16_t local_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS]; /** --ike-ports */
    uint16_t remote_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];     /** --ike-ports */
    uint16_t remote_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS];/** --ike-ports */
    bool dhcp_ras_enabled;                           /** -R */
    const char *enable_key_restrictions;             /** -N */
};

typedef struct SshIpmParamsRec SshIpmParamsStruct;

#endif /* not SSHQUICKSECPM_XMLCONF_H */
