/**
   @copyright
   Copyright (c) 2013 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#include "ipsec_policy.h"

#include "implementation_defs.h"

#define __DEBUG_MODULE__ PmSpdAccess

static int
spd_access_request_cb(
        void *param,
        SshIpAddr local_address,
        SshIpAddr remote_address,
        int in_protocol,
        int local_port,
        int remote_port)
{
    SshPm pm = param;
    struct InAddr local_address_inaddr;
    struct InAddr remote_address_inaddr;
    struct InAddr *local_address_inaddr_p = NULL;
    struct InAddr *remote_address_inaddr_p = NULL;
    int policy_entry_id;
    bool ok = true;

    if (ok == true)
    {
        if (local_address != NULL)
        {
            in_addr_convert_from_sshipaddr(
                    &local_address_inaddr,
                    local_address);

            local_address_inaddr_p = &local_address_inaddr;
        }

        if (remote_address != NULL)
        {
            in_addr_convert_from_sshipaddr(
                    &remote_address_inaddr,
                    remote_address);

            remote_address_inaddr_p = &remote_address_inaddr;
        }

        ok =
            ipsec_policy_add_5tuple_bypass_entry(
                    pm->ipsec_control,
                    local_address_inaddr_p,
                    remote_address_inaddr_p,
                    in_protocol,
                    local_port,
                    remote_port,
                    &policy_entry_id);
    }

    if (ok == false)
    {
        policy_entry_id = -1;
    }

    return policy_entry_id;
}

static void
spd_access_release_cb(
        void *param,
        int handle,
        int delay_seconds)
{
    SshPm pm = param;

    ipsec_policy_remove_entry_with_delay(
            pm->ipsec_control,
            handle,
            delay_seconds);
}

void
spd_access_init(
        SshPm pm)
{
    ssh_inet_access_callbacks_set(
            spd_access_request_cb,
            spd_access_release_cb,
            pm);

    DEBUG_HIGH(init, "Spd access callbacks initialised.");
}


void
spd_access_cleanup(
        void)
{
    ssh_inet_access_callbacks_set(NULL, NULL, NULL);

    DEBUG_HIGH(init, "Spd access callbacks deinitialised.");
}
