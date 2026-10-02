/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Netevent listener module.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshnetconfig.h"
#include "sshnetevent.h"

#define SSH_DEBUG_MODULE "SshPmNeteventListener"

/* The interval (in microseconds) after an interface change will be handled. */
#define SSH_PM_NETEVENT_TIMER_INTERVAL  250000

static void
pm_netevent_interface_change(
        SshPm pm)
{
    SSH_DEBUG(SSH_D_LOWOK, ("Interface change."));

    /* Update interface information. */
    ssh_pm_interface_change(pm);

    /* Notify the main thread that the interface information has
       changed. */
    pm->iface_change = 1;
    ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
}

static void
pm_netevent_timeout_cb(
        void *context)
{
    SshPm pm = (SshPm) context;

    pm->netevent_timer_registered = false;

    pm_netevent_interface_change(pm);
}

static void
pm_netevent_timer_start(
        SshPm pm)
{
    if (pm->netevent_timer_registered == false)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Start netevent timer."));

        ssh_register_timeout(
                &pm->netevent_timer,
                0,
                SSH_PM_NETEVENT_TIMER_INTERVAL,
                pm_netevent_timeout_cb,
                pm);
        pm->netevent_timer_registered = true;
    }
}

static void
pm_netevent_timer_stop(
        SshPm pm)
{
    if (pm->netevent_timer_registered == true)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Cancel netevent timer."));

        ssh_cancel_timeout(&pm->netevent_timer);
        pm->netevent_timer_registered = false;
    }
}


/*  XXX this function is just a place holder for a future handling of
 *  routes changed event */
static void
pm_netevent_routes_changed(
        void)
{
    SSH_DEBUG(SSH_D_LOWOK, ("Routes changed event received"));
}

static void
pm_netevent_callback(
        SshNetconfigEvent event,
        uint32_t ifnum,
        void *context)
{
    SshPm pm = context;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Received netevent %x for ifnum %d", (int) event, (int) ifnum));

    switch (event)
    {
    case SSH_NETCONFIG_EVENT_LINK_CHANGED:
    case SSH_NETCONFIG_EVENT_ADDRESS_CHANGED:
        pm_netevent_timer_start(pm);
        break;
    case SSH_NETCONFIG_EVENT_ROUTES_CHANGED:
        pm_netevent_routes_changed();
        break;
    case SSH_NETCONFIG_EVENT_LAST:
    default:
        SSH_DEBUG(SSH_D_ERROR, ("Unkown netconfig event"));
        break;
    }
}

bool
ssh_pm_netevent_listener_init(
        SshPm pm)
{
    if (pm->netevent_handle != NULL)
        return false;

    pm->netevent_handle =
        ssh_netconfig_register_event_callback(pm_netevent_callback, pm);
    if (pm->netevent_handle == NULL)
        return false;

    pm->netevent_timer_registered = false;
    return true;
}

void
ssh_pm_netevent_listener_uninit(
        SshPm pm)
{
    pm_netevent_timer_stop(pm);

    if (pm->netevent_handle != NULL)
        ssh_netconfig_unregister_event_callback(pm->netevent_handle);

    pm->netevent_handle = NULL;
}
