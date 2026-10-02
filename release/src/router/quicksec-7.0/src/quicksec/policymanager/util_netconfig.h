/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/


#ifndef UTIL_NETCONFIG_H
#define UTIL_NETCONFIG_H

bool ssh_pm_interface_change(SshPm pm);

int
ssh_pm_route(
        SshPm pm,
        SshIpAddr preferred_src,
        SshRouteKey key,
        uint32_t *flags,
        uint32_t *ifnum,
        SshIpAddr next_hop);

void
ssh_pm_qm_route(
        SshPm pm,
        uint32_t flags,
        uint32_t ifnum,
        const SshIpAddr next_hop,
        void *context);



/** Initialize netevent listener for receiving interface information
    from the kernel.

    @param pm
    Policymanager object

    @return
    This returns true if the netevent listener was successfully registered
    and false otherwise.
*/
bool ssh_pm_netevent_listener_init(SshPm pm);

/** Uninitialize netevent listener.

    @param pm
    Policymanager object

*/
void ssh_pm_netevent_listener_uninit(SshPm pm);

#endif /* UTIL_NETCONFIG_H */
