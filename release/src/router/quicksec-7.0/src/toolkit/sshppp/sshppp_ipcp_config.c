/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppIpcpConfig"

#include "sshincludes.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshtime.h"
#include "sshcrypt.h"
#include "sshinet.h"
#include "sshbuffer.h"

#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */

#include "sshppp_linkpkt.h"
#include "sshppp_events.h"
#include "sshppp.h"
#include "sshppp_config.h"
#include "sshppp_flush.h"
#include "sshppp_auth.h"
#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_protocol.h"
#include "sshppp_lcp_config.h"
#include "sshppp_lcp.h"
#include "sshppp_ipcp_config.h"
#include "sshppp_ipcp.h"


bool
ssh_ppp_ipcp_config_init(SshIpcpConfig config, uint8_t max_iters)
{
    int ok;
    bool ret;

    ok = 1;

    ret = ssh_ppp_config_option_init_ipv4(&config->ip,
                            SSH_IPCP_CONFIG_TYPE_IP_ADDRESS,max_iters);

    ok &= (ret == true ? 1 : 0);

#ifdef SSHDIST_RADIUS
    ret = ssh_ppp_config_option_init_ipv4(&config->radius_ip,
                            SSH_IPCP_CONFIG_TYPE_IP_ADDRESS,max_iters);

    config->use_radius_ip = false;

    ok &= (ret == true ? 1 : 0);
#endif /* SSHDIST_RADIUS */

    ret = ssh_ppp_config_option_init_ipv4(&config->dns_primary,
                            SSH_IPCP_CONFIG_TYPE_DNS_PRIMARY,max_iters);

    ok &= (ret == true ? 1 : 0);

    ret = ssh_ppp_config_option_init_ipv4(&config->dns_secondary,
                                    SSH_IPCP_CONFIG_TYPE_DNS_SECONDARY,
                                    max_iters);

    ok &= (ret == true ? 1: 0);


    ret = ssh_ppp_config_option_init_ipv4(&config->nbns_primary,
                                    SSH_IPCP_CONFIG_TYPE_NBNS_PRIMARY,
                                    max_iters);

    ok &= (ret == true ? 1: 0);


    ret = ssh_ppp_config_option_init_ipv4(&config->nbns_secondary,
                                    SSH_IPCP_CONFIG_TYPE_NBNS_SECONDARY,
                                    max_iters);

    ok &= (ret == true ? 1:0);

    return (ok ? true : false);
}

#ifdef SSHDIST_RADIUS
void
ssh_ppp_ipcp_use_radius(SshIpcpConfig ipcp_config, bool useit)
{
    ipcp_config->use_radius_ip = useit;
}

bool
ssh_ppp_ipcp_is_radius(SshIpcpConfig ipcp_config)
{
    return ipcp_config->use_radius_ip;
}

#endif /* SSHDIST_RADIUS */

bool
ssh_ppp_ipcp_config_init_supported(SshIpcpConfig config)
{
    return ssh_ppp_ipcp_config_init(config, 2);
}

SshPppConfigOption
ssh_ppp_ipcp_config_get_option_input(SshPppState state,
                                     void *ctx, uint8_t type)
{
    return ssh_ppp_ipcp_config_get_option(&(((SshIpcpLocal)ctx)->config_input),
                                          type);
}

SshPppConfigOption
ssh_ppp_ipcp_config_get_option_output(SshPppState state,
                                      void *ctx, uint8_t type)
{
    SshPppConfigOption opt;

    opt = ssh_ppp_ipcp_config_get_option(&(((SshIpcpLocal)ctx)->config_output),
                                         type);
    return opt;
}

SshPppConfigOption
ssh_ppp_ipcp_config_get_option(SshIpcpConfig config, uint8_t type)
{
    switch (type)
    {
      case SSH_IPCP_CONFIG_TYPE_IP_ADDRESS:
#ifdef SSHDIST_RADIUS
        if (config->use_radius_ip == 1)
          return &config->radius_ip;
#endif /* SSHDIST_RADIUS */
        return &config->ip;
      case SSH_IPCP_CONFIG_TYPE_DNS_PRIMARY:
        return &config->dns_primary;
      case SSH_IPCP_CONFIG_TYPE_DNS_SECONDARY:
        return &config->dns_secondary;
      case SSH_IPCP_CONFIG_TYPE_NBNS_PRIMARY:
        return &config->nbns_primary;
      case SSH_IPCP_CONFIG_TYPE_NBNS_SECONDARY:
        return &config->nbns_secondary;
    }
    return NULL;
}

SshPppConfigOption
ssh_ppp_ipcp_config_iter_option_input(SshPppState state,
                                      void *ctx, int i)

{
    SshPppConfigOption opt;
    opt = ssh_ppp_ipcp_config_iter_option(&(((SshIpcpLocal)ctx)->config_input),
                                          i);
    return opt;
}

SshPppConfigOption
ssh_ppp_ipcp_config_iter_option_output(SshPppState state, void* ctx, int i)
{
    SshPppConfigOption opt;
    opt=ssh_ppp_ipcp_config_iter_option(&(((SshIpcpLocal)ctx)->config_output),
                                        i);
    return opt;
}

SshPppConfigOption
ssh_ppp_ipcp_config_iter_option(SshIpcpConfig config, int i)
{
    switch (i)
    {
      case 0:
#ifdef SSHDIST_RADIUS
        if (config->use_radius_ip == 1)
          return &config->radius_ip;
#endif /* SSHDIST_RADIUS */
        return &config->ip;
      case 1:
        return &config->dns_primary;
      case 2:
        return &config->dns_secondary;
      case 3:
        return &config->nbns_primary;
      case 4:
        return &config->nbns_secondary;
    }
    return NULL;
}

void
ssh_ppp_ipcp_config_free(SshIpcpConfig config)
{
    ssh_ppp_config_option_uninit(&config->ip);
#ifdef SSHDIST_RADIUS
    ssh_ppp_config_option_uninit(&config->radius_ip);
#endif /* SSHDIST_RADIUS */
    ssh_ppp_config_option_uninit(&config->dns_primary);
    ssh_ppp_config_option_uninit(&config->dns_secondary);
    ssh_ppp_config_option_uninit(&config->nbns_primary);
    ssh_ppp_config_option_uninit(&config->nbns_secondary);
}
