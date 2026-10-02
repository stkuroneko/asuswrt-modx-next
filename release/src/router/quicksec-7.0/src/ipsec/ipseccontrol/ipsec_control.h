/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/


#ifndef IPSEC_CONTROL_H
#define IPSEC_CONTROL_H

#include "public_defs.h"
#include "ipsec_sa_params.h"
#include "ipsec_policy_params.h"

/**
   @file
   IPsec control API. Callbacks declarations used by IPsec control.
*/

struct IPsecControl;

/**
    Callback for installing SA's in both directions (inbound/outbound)
    to dataplane.

    @param control_p
    Registered control context pointer.

    @param params
    SA parameters.

    @param endpoints
    Endpoints for the SA and policy.

    @param control_sa_p
    Pointer to pointer for registering per SA context.

    @param key_mat
    Key material.

    @return
    True for success, false for failure.
 */
typedef bool
IPsecControlInstallSaCB(
        void *control_p,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *endpoints,
        void **control_sa_p,
        const struct IPsecSaKeyMaterial *key_mat);

/**
    Callback for installing inbound SA's to dataplane.

    @param control_p
    Registered control context pointer.

    @param params
    SA parameters.

    @param endpoints
    Endpoints for the SA.

    @param control_sa_p
    Pointer to pointer for registering per SA context.

    @param key_mat
    Key material.

    @return
    True for success, false for failure.
 */
typedef bool
IPsecControlInstallInboundSaCB(
        void *control_p,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *endpoints,
        void **control_sa_p,
        const struct IPsecSaKeyMaterial *key_mat);

/**
    Callback for installing outbound SA's to dataplane. Must be called only
    after installing inbound SA's.

    @param control_p
    Registered control context pointer.

    @param params
    SA parameters.

    @param endpoints
    Endpoints for the SA and policy.

    @param control_sa_p
    Registered per SA context.

    @param key_mat
    Key material.

    @return
    True for success, false for failure.
 */

typedef bool
IPsecControlInstallOutboundSaCB(
        void *control_p,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *endpoints,
        void *control_sa_p,
        const struct IPsecSaKeyMaterial *key_mat);

/**
    Callback for updating existing SA's endpoints.
    to dataplane.

    @param control_p
    Registered control context pointer.

    @param params
    SA parameters.

    @param old_endpoints
    Old endpoints for the SA.

    @param new_endpoints
    New endpoints for the SA.

    @param control_sa
    Registered per SA context.

    @return
    True if the dataplane supports updating the SA or false if it doesn't.
 */
typedef bool
IPsecControlUpdateSaCB(
        void *control_p,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *old_endpoints,
        const struct IPsecSaEndpoints *new_endpoints,
        void *control_sa);
/**
    Callback for removing SA's and policies from dataplane.

    @param control_p
    Registered control context pointer.

    @param params
    SA parameters.

    @param endpoints
    Endpoints for the SA and policy.

    @param control_sa
    Registered per SA context.
 */
typedef void
IPsecControlRemoveSaCB(
        void *control_p,
        const struct IPsecSaParams *params,
        const struct IPsecSaEndpoints *endpoints,
        void *control_sa);

/**
    Callback for installing a policy to the data plane

    @param control_p
    Registered control context pointer.

    @param params
    Policy parameters.

    @param control_policy_p
    Pointer to pointer for registering per policy context.

    @return
    True for success, false for failure.

 */
typedef bool
IPsecControlInstallPolicyCB(
        void *control_p,
        const struct IPsecPolicyParams *params,
        void **control_policy_p);


/**
   Callback for updating a policy in the data plane

    @param control_p
    Registered control context pointer.

    @param params
    Policy parameters.

    @param control_policy_p
    Registered per policy context.

    @return
    True for success, false for failure.
 */
typedef bool
IPsecControlUpdatePolicyCB(
        void *control_p,
        const struct IPsecPolicyParams *params,
        const struct IPsecSaEndpoints *endpoints,
        void *control_policy_p);

/**
    Callback for deleting a policy from the data plane

    @param control_p
    Registered control context pointer.

    @param params
    Policy parameters.

    @param control_policy_p
    Registered per policy context.

    @return
    True for success, false for failure.
 */
typedef void
IPsecControlDeletePolicyCB(
        void *control_p,
        const struct IPsecPolicyParams *params,
        void **control_policy_p);


/** See function prototypes for descriptions */
struct IPsecControlCallbacks
{
    IPsecControlInstallSaCB *install_sa_cb;
    IPsecControlInstallInboundSaCB *install_inbound_sa_cb;
    IPsecControlInstallOutboundSaCB *install_outbound_sa_cb;
    IPsecControlUpdateSaCB *update_sa_cb;
    IPsecControlRemoveSaCB *remove_sa_cb;
    IPsecControlInstallPolicyCB *install_policy_cb;
    IPsecControlUpdatePolicyCB *update_policy_cb;
    IPsecControlDeletePolicyCB *delete_policy_cb;
};

/**
    Registers context callbacks to IPsecControl object.

    @param ipsec_control
    IPsecControl pointer

    @param control_callbacks
    Callbacks to be registered.

    @param control_param
    Control context pointer that will be 'control_p' of the callbacks
 */
void
ipsec_control_register_context_callbacks(
        struct IPsecControl *ipsec_control,
        const struct IPsecControlCallbacks *control_callbacks,
        void *control_param);

/**
    Unregisters the callbacks from IPsecControl object.

    @param ipsec_control
    IPsecControl pointer

    @param control_callbacks
    Callbacks to be unregistered.

    @param control_param
    Registered control context pointer.
 */
void
ipsec_control_unregister_context_callbacks(
        struct IPsecControl *ipsec_control,
        const struct IPsecControlCallbacks *control_callbacks,
        void *control_param);

/**
    Sends an data plane event to IPsecControl.

    @param ipsec_control
    IPsecControl pointer

    @param event_id
    Event ID.

    @param spi
    SPI

    @param overflow
    True if this is a sequence overflow event.

    @param  first_packet
    True if this is a first packet event.

    @param rekey
    True if this is a rekey event.

    @param idle_timeout
    True if this an idle timeout event.
 */
void
ipsec_control_sa_event(
        struct IPsecControl *ipsec_control,
        uint32_t event_id,
        uint32_t spi,
        bool overflow,
        bool first_packet,
        bool rekey,
        bool idle_timeout);


/**
    Function to deliver an unknown SPI event from data plane.

    @param control_p
    Registered control context pointer.

    @param unknown_spi_event_id
    Event ID.

    @param local_address
    Local IP.

    @param remote_address
    Remote IP.

    @param local_port
    Local port.

    @param remote_port
    Remote port.

    @param protocol
    Protocol number.

    @param spi
    SPI

    @param routing_instance_id
    VRF id.
 */
void
ipsec_control_unknown_spi_event(
        void *control_p,
        const struct InAddr *local_address,
        const struct InAddr *remote_address,
        int local_port,
        int remote_port,
        int protocol,
        uint32_t spi,
        int routing_instance_id);

#endif /* IPSEC_CONTROL_H */
