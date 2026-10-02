/**
   @copyright
   Copyright (c) 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec Control init module.
*/
#include "sshincludes.h"

#include "ipsec_control_init.h"
#include "ipsec_sa.h"
#include "ipsec_control.h"

#include "ipsec_control_internal.h"

#define SSH_DEBUG_MODULE "IPsecControlInit"
#define __DEBUG_MODULE__ IPsecControlInit


void
ipsec_control_register_context_callbacks(
        struct IPsecControl *ipsec_control,
        const struct IPsecControlCallbacks *control_callbacks,
        void *control_param)
{
    ipsec_control->control_callbacks = control_callbacks;
    ipsec_control->control_param = control_param;
}


void
ipsec_control_unregister_context_callbacks(
        struct IPsecControl *ipsec_control,
        const struct IPsecControlCallbacks *control_callbacks,
        void *control_param)
{
    if (ipsec_control != NULL)
    {
        ipsec_control->control_callbacks = NULL;
        ipsec_control->control_param = NULL;
    }
}


bool
ipsec_control_init(
        struct IPsecControl **ipsec_control_p)
{
    struct IPsecControl *ipsec_control = NULL;
    bool success = true;

    ipsec_control = ssh_calloc(1, sizeof *ipsec_control);
    if (ipsec_control == NULL)
    {
        IPSEC_CONTROL_DEBUG(FAIL, ipsec_control, "Out of memory!");
        success = false;
    }

    if (success == true)
    {
        success =
            ipsec_control_db_init(
                    ipsec_control);
    }

    if (success == true)
    {
        *ipsec_control_p = ipsec_control;

        IPSEC_CONTROL_DEBUG(
                HIGH,
                *ipsec_control_p,
                "initialized.");
    }
    else
    {
        ipsec_control_uninit(&ipsec_control);

        IPSEC_CONTROL_DEBUG(
                FAIL,
                NULL,
                "initialization failed.");
    }

    return success;
}

void
ipsec_control_flush(
        struct IPsecControl *ipsec_control)
{
    if (ipsec_control != NULL)
        ipsec_policy_flush(ipsec_control);
}

void
ipsec_control_uninit(
        struct IPsecControl **ipsec_control_p)
{
    if (*ipsec_control_p != NULL)
    {
        struct IPsecControl *ipsec_control = *ipsec_control_p;

        ipsec_sa_unconfigure(ipsec_control);

        ipsec_control_db_uninit(ipsec_control);

        IPSEC_CONTROL_DEBUG(
                HIGH,
                ipsec_control,
                "uninitialized.");

        ssh_free(ipsec_control);
        *ipsec_control_p = NULL;
    }
}
