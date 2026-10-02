/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPSec SA handler.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#include "idtransformer.h"

#define SSH_DEBUG_MODULE "SshPmSaHandler"


struct IPSelectorGroup *
ssh_pm_create_ip_selector_group(
        const struct SshIkev2PayloadTSRec *ike_local_ts,
        const struct SshIkev2PayloadTSRec *ike_remote_ts)
{
    struct IPSelectorGroup *selector_group;
    int selector_size =
        ip_selector_convert_group_bytecount_ikev2ts(
                ike_local_ts,
                ike_remote_ts);

    selector_group = ssh_malloc(selector_size);

    if (selector_group != NULL)
    {
        ip_selector_convert_from_ikev2ts(
                selector_group,
                selector_size,
                ike_local_ts,
                ike_remote_ts);
    }

    return selector_group;
}

void
ssh_pm_free_selector_group(
        struct IPSelectorGroup *selector_group)
{
    ssh_free(selector_group);
}



/* TransformId to IKEv2 Transform ID mapping ********************************/

#define ICM_IKEV2_TRANSFORM_ATTR_KEYLEN(_attr) \
  (((_attr) & 0x800e0000) != 0 ? ((_attr) & 0xffff) : 0)

typedef struct ICMIkev2TransformIdMapRec
{
  TransformId id;
  uint32_t ike_id;
} ICMIkev2TransformIdMapStruct;

#define SSH_IKEV2_TRANSFORM_INVALID 0xffff


static const ICMIkev2TransformIdMapStruct icm_ikev2_transformid_integ[] = {
    { TRANSFORMID_INTEG_HMAC_MD5_96, SSH_IKEV2_TRANSFORM_AUTH_HMAC_MD5_96},
    { TRANSFORMID_INTEG_HMAC_SHA1_96, SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA1_96},
    { TRANSFORMID_INTEG_AES_XCBC_96, SSH_IKEV2_TRANSFORM_AUTH_AES_XCBC_96},
    { TRANSFORMID_INTEG_HMAC_SHA256_128,
      SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA256_128},
    { TRANSFORMID_INTEG_HMAC_SHA384_192,
      SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA384_192},
    { TRANSFORMID_INTEG_HMAC_SHA512_256,
      SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA512_256},
    { TRANSFORMID_INTEG_AES_128_GMAC,
      SSH_IKEV2_TRANSFORM_AUTH_AES_128_GMAC_128},
    { TRANSFORMID_INTEG_AES_192_GMAC,
      SSH_IKEV2_TRANSFORM_AUTH_AES_192_GMAC_128},
    { TRANSFORMID_INTEG_AES_256_GMAC,
      SSH_IKEV2_TRANSFORM_AUTH_AES_256_GMAC_128},

    { TRANSFORMID_INVALID, SSH_IKEV2_TRANSFORM_INVALID}
};


static TransformId
icm_ikev2_ike_integ_id_to_transformid(SshIkev2TransformID ike_id)
{
    int i;

    for (i = 0; true; i++)
    {
        if (icm_ikev2_transformid_integ[i].id == TRANSFORMID_INVALID
            || icm_ikev2_transformid_integ[i].ike_id == ike_id)
            return icm_ikev2_transformid_integ[i].id;
    }
}



static TransformId
ipsec_sa_transformid_from_ikev2_encryption_transform(
        SshIkev2PayloadTransform encryption_transform)
{
    TransformId encryption_id = TRANSFORMID_ENCR_NULL;

    if (encryption_transform != NULL)
    {
        unsigned int encr_key_len;

        encr_key_len =
            ICM_IKEV2_TRANSFORM_ATTR_KEYLEN(
                    encryption_transform->transform_attribute);

        encryption_id =
            idtransformer_id_from_ikev2_encr_id(
                    encryption_transform->id,
                    encr_key_len);

        if (encryption_id == TRANSFORMID_INVALID)
        {
            SSH_DEBUG(SSH_D_FAIL,
                ("Invalid IPsec SA encryption algorithm id 0x%lx",
                (unsigned long) encryption_transform->id));
        }
    }

  return encryption_id;
}

static TransformId
ipsec_sa_transformid_from_ikev2_integrity_transform(
        SshIkev2PayloadTransform integrity_transform)
{
    TransformId integrity_id = TRANSFORMID_INTEG_NONE;

    if (integrity_transform != NULL)
    {
        integrity_id =
            icm_ikev2_ike_integ_id_to_transformid(
                    integrity_transform->id);

        if (integrity_id == TRANSFORMID_INVALID)
        {
            SSH_DEBUG(SSH_D_FAIL,
                ("Invalid IPsec SA integrity algorithm id 0x%08lx",
                (unsigned long) integrity_transform->id));
        }
    }

    return integrity_id;
}


/***************************** IPSec SA handler *****************************/

static bool
pm_ipsec_sa_mac_key_material_size(
        SshPm pm,
        SshIkev2PayloadTransform *transforms,
        int *mac_key_material_size)
{
    SshIkev2PayloadTransform trans;
    SshPmMac mac;
    size_t key_size = 0;

    /* Integrity; now the ESP MAC, in future AH as well */
    trans = transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG];
    if (trans != NULL && trans->id != SSH_IKEV2_TRANSFORM_AUTH_NONE)
    {
        mac = ssh_pm_ipsec_mac_by_id(pm, trans->id);
        if (mac == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Unsupported Auth mac, transform id %d",
                                   trans->id));
            return false;
        }

        key_size = mac->default_key_size / 8;
    }

    *mac_key_material_size = key_size;

    return true;
}

static bool
pm_ipsec_sa_enc_key_material_size(
        SshPm pm,
        SshIkev2PayloadTransform *transforms,
        int *enc_key_material_size)
{
    SshIkev2PayloadTransform trans;
    SshPmCipher cipher;
    int cipher_key_size = 0;
    int cipher_nonce_size = 0;

    trans = transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR];
    if (trans != NULL)
    {
        cipher = ssh_pm_ipsec_cipher_by_id(pm, trans->id);
        if (cipher == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Unsupported cipher with transform id %d",
                                   trans->id));
            return false;
        }

        if (trans->transform_attribute & 0x800e0000)
        {
            cipher_key_size = (trans->transform_attribute & 0xffff) / 8;
        }
        else
        {
            cipher_key_size = cipher->default_key_size / 8;
        }

        /* The nonce for counter mode */
        cipher_nonce_size = cipher->nonce_size / 8;
    }

    *enc_key_material_size = cipher_key_size + cipher_nonce_size;

    return true;
}


static bool
pm_ipsec_fill_keymaterials(
        SshIkev2ExchangeData ed,
        SshPmQm qm)
{
    struct IPsecSaKeyMaterial *ipsec_sa_keymaterial =
        &qm->ipsec_sa_keymaterial;
    const int keymaterial_len =
      ipsec_sa_keymaterial->integrity_keymaterial_len +
      ipsec_sa_keymaterial->encryption_keymaterial_len;

    unsigned char keymat[SSH_IPSEC_MAX_KEYMAT_LEN];

    SSH_ASSERT((2 * keymaterial_len) <= sizeof(keymat));

    if (ssh_ikev2_fill_keymat(ed, keymat, 2 * keymaterial_len) !=
                SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Cannot generate key material"));
        return false;
    }

    /*
     The order of key materials for inbound and outbound SAs depend on
     being initiator or responder, and using IKEv1.
    */
    {
        bool outbound_first = qm->initiator;
        unsigned char *outbound_encryption;
        unsigned char *outbound_integrity;
        unsigned char *inbound_encryption;
        unsigned char *inbound_integrity;

#ifdef SSHDIST_IKEV1
        if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        {
            outbound_first = false;
        }
#endif /* SSHDIST_IKEV1 */

        if (outbound_first == true)
        {
            outbound_encryption = keymat;
            inbound_encryption = keymat + keymaterial_len;
        }
        else
        {
            inbound_encryption = keymat;
            outbound_encryption = keymat + keymaterial_len;
        }

        outbound_integrity =
                outbound_encryption +
                ipsec_sa_keymaterial->encryption_keymaterial_len;

        inbound_integrity =
                inbound_encryption +
                ipsec_sa_keymaterial->encryption_keymaterial_len;

        memcpy(ipsec_sa_keymaterial->outbound_encryption_keymaterial,
                outbound_encryption,
                ipsec_sa_keymaterial->encryption_keymaterial_len);

        memcpy(ipsec_sa_keymaterial->outbound_integrity_keymaterial,
                outbound_integrity,
                ipsec_sa_keymaterial->integrity_keymaterial_len);

        memcpy(ipsec_sa_keymaterial->inbound_encryption_keymaterial,
                inbound_encryption,
                ipsec_sa_keymaterial->encryption_keymaterial_len);

        memcpy(ipsec_sa_keymaterial->inbound_integrity_keymaterial,
                inbound_integrity ,
                ipsec_sa_keymaterial->integrity_keymaterial_len);
    }

    return true;
}


static SshIkev2Error
ipsec_sa_handle_peer(
        SshPm pm,
        SshPmQm qm)
{
    SshPmP1 p1 = qm->p1;
    SshIkev2Error status = SSH_IKEV2_ERROR_OK;

    if (status == SSH_IKEV2_ERROR_OK)
    {
        if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
        {
            /* Check if there is a known peer for p1. */
            qm->peer_handle = ssh_pm_peer_handle_by_p1(pm, p1);

            /* Take a reference to peer handle to protect qm->peer_handle. */
            if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
                ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
        }
        else
        {
            /* This is an IPsec SA responder rekey that has created a new
               IKEv1 SA, or this is a restarted initiator IPsec SA negotiation
               that was originally started with an expired IKEv1 SA and now
               it has completed after having created a new IKEv1 SA. Update the
               IKE SA to the existing peer. */
            SSH_ASSERT(ssh_pm_peer_by_handle(pm, qm->peer_handle) != NULL);
            if (ssh_pm_peer_update_p1(
                        pm,
                        ssh_pm_peer_by_handle(
                                pm,
                                qm->peer_handle),
                        p1)
                == false)
            {
                SSH_DEBUG(SSH_D_ERROR,
                          ("Qm peer update by peer failed."));

                status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }
        }
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        /* No suitable peer handle found, create new. */
        if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
        {
            /* On success the created peer has been initialized with one
               reference for the p1 (if there was one) and one reference for
               the caller of the function. Use the latter reference to protect
               qm->peer_handle.
            */

            qm->peer_handle =
                ssh_pm_peer_create(
                        pm,
                        p1->tunnel_id,
                        p1->ike_sa->remote_ip,
                        p1->ike_sa->remote_port,
                        p1->ike_sa->server->ip_address,
                        SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa),
                        p1,
                        qm->tunnel->routing_instance_id);
            if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
            {
                SSH_DEBUG(SSH_D_ERROR,
                          ("Qm peer creation failed."));

                status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }
        }
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        if (qm->rekey != 0)
        {
            if (!ssh_pm_peer_update_p1(
                         pm,
                         ssh_pm_peer_by_handle(
                                 pm,
                                 qm->peer_handle),
                         p1))
            {
                SSH_DEBUG(SSH_D_ERROR,
                          ("Qm peer update failed."));

                status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }
            else
            {
                /*
                  For rekeys, update p1 to peer. Assert that p1 is valid
                  because rekeys never happen for manually keyed IPsec
                  SAs. Also assert that qm->peer_handle is set and
                  valid. For IKEv2 responder IPsec SA rekey negotiations
                  qm->peer_handle is set when allocating SPIs, for IKEv1
                  responder IPsec SA rekey negotiations qm->peer_handle
                  was set during responder rekey check.
                */
                SSH_PM_ASSERT_P1(qm->p1);
                SSH_ASSERT(qm->peer_handle != SSH_IPSEC_INVALID_INDEX);
                SSH_ASSERT(ssh_pm_peer_by_handle(pm, qm->peer_handle) != NULL);
            }
        }
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        /* Ok, now we have a valid peer_handle. Take one reference for
           this IPsec SA. */
        ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);

        /* Set transform ike_sa_handle point to peer and mark that the
           peer_handle reference must be explicitly freed in error cases
           happening before the SA has been successfully installed. */
        qm->delete_peer_ref_on_error = 1;
    }
    else
    {
        qm->peer_handle = SSH_IPSEC_INVALID_INDEX;
    }

    return status;
}

static void
ipsec_sa_calculate_lifetimes(
        SshPmP1 p1,
        SshIkev2ExchangeData ed,
        SshPmTunnel tunnel,
        bool initiator,
        uint32_t *life_seconds_p,
        uint64_t *life_bytes_p)
{
    /* Lifetimes are negotiated for IKEv1 SA's, the negotiated value is
       set to the IKE exchange data. For IKEv2 SA's we use the value
       from the local policy. */

#ifdef SSHDIST_IKEV1
    if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
        *life_seconds_p = ed->ipsec_ed->sa_life_seconds;
        *life_bytes_p = (uint64_t) ed->ipsec_ed->sa_life_kbytes * 1024;

        if (!initiator &&
            ((p1->compat_flags & SSH_PM_COMPAT_DONT_INITIATE)
             || p1->ike_sa->xauth_done))
        {
            /* Increase the lifetimes by 20% if we know the remote peer
               is not able to act as a responder. This disregards somewhat
               the negotiated policy, however not doing this causes
               interopability problems as many vendors do not use slightly
               shorter lifetimes as an initiator even though they cannot act
               as a responder. Note that increasing the lifetimes in this
               manner is only effective for IKEv1 SA's. */
            uint32_t life_seconds;
            uint64_t life_bytes;

            life_seconds = *life_seconds_p;
            if (life_seconds > 0)
            {
                *life_seconds_p = life_seconds + (life_seconds / 5);

                if (*life_seconds_p < life_seconds)
                {
                    *life_seconds_p = 0;
                }
            }

            life_bytes = *life_bytes_p;
            if (life_bytes > 0)
            {
                *life_bytes_p = life_bytes + (life_bytes / 5);

                if (*life_bytes_p < life_bytes)
                {
                    *life_bytes_p = 0;
                }
            }
        }
    }
    else
#endif /* SSHDIST_IKEV1 */
    {
        *life_seconds_p = tunnel->u.ike.ipsec_sa_life_seconds;
        *life_bytes_p = (uint64_t) tunnel->u.ike.ipsec_sa_life_kb * 1024;
    }
    if (*life_seconds_p == 0)
        *life_seconds_p = SSH_PM_DEFAULT_IPSEC_SA_LIFE_SECONDS;
}

static void
ipsec_sa_configure_params(
        SshPm pm,
        SshPmQm qm,
        SshIkev2ExchangeData ed,
        uint32_t outbound_spi,
        SshInetIPProtocolID ipproto)
{
    SshPmP1 p1 = qm->p1;
    struct IPsecSaParams *ipsec_sa_params = &qm->ipsec_sa_params;
    struct IPsecSaEndpoints *ipsec_sa_endpoints = &qm->ipsec_sa_endpoints;
    SshPmTunnel tunnel = qm->tunnel;
    bool initiator = qm->initiator;
    bool dpd_enabled = true;
    bool is_ikev1 = false;

#ifdef SSHDIST_IKEV1
    if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
        is_ikev1 = true;
    }
#endif /* SSHDIST_IKEV1 */

    ipsec_sa_params->log_facility = SSH_LOGFACILITY_DAEMON;
    ipsec_sa_params->tunnel_id = tunnel->tunnel_id;

    ipsec_sa_params->policy_priority = IPSEC_PRIORITY_SA_LOW;

    /** Encryption algorithm identifier including key length specifier */
    ipsec_sa_params->encryption_algorithm_id =
      ipsec_sa_transformid_from_ikev2_encryption_transform(
              ed->ipsec_ed->ipsec_sa_transforms[
                      SSH_IKEV2_TRANSFORM_TYPE_ENCR]);


    /** Auth algorithm identifier including digest length specifier */
    ipsec_sa_params->integrity_algorithm_id =
      ipsec_sa_transformid_from_ikev2_integrity_transform(
              ed->ipsec_ed->ipsec_sa_transforms[
                      SSH_IKEV2_TRANSFORM_TYPE_INTEG]);

#ifdef SSHDIST_L2TP
    /* Enable L2TP iff. both local and remote have just one TS item, and
       either the local or remote TS item is UDP on port 1701. */
    if (qm->local_ts && qm->local_ts->number_of_items_used == 1 &&
        qm->remote_ts->number_of_items_used == 1 &&
        ((qm->local_ts->items->proto == SSH_IPPROTO_UDP &&
          qm->local_ts->items->start_port == SSH_IPSEC_L2TP_PORT &&
          qm->local_ts->items->end_port == SSH_IPSEC_L2TP_PORT) ||
         (qm->remote_ts->items->proto == SSH_IPPROTO_UDP &&
          qm->remote_ts->items->start_port == SSH_IPSEC_L2TP_PORT &&
          qm->remote_ts->items->end_port == SSH_IPSEC_L2TP_PORT)))
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("[qm %p] Enabling L2TP encapsulation", qm));

        SSH_ASSERT(false);
    }
#endif /* SSHDIST_L2TP */

    ipsec_sa_params->ikev1_sa = is_ikev1;

    ipsec_sa_params->inbound_spi = ed->ipsec_ed->spi_inbound;
    ipsec_sa_params->outbound_spi = outbound_spi;

    ipsec_sa_params->initiator = initiator;

    /* Replace the qm->{local,remote}_ts with proper narrowed values */
    if (qm->local_ts)
        ssh_ikev2_ts_free(pm->sad_handle, qm->local_ts);
    if (qm->remote_ts)
        ssh_ikev2_ts_free(pm->sad_handle, qm->remote_ts);

    qm->local_ts = qm->ed->ipsec_ed->ts_local;
    qm->remote_ts = qm->ed->ipsec_ed->ts_remote;
    ssh_ikev2_ts_take_ref(pm->sad_handle, qm->local_ts);
    ssh_ikev2_ts_take_ref(pm->sad_handle, qm->remote_ts);

    if (!(qm->transport_sent && qm->transport_recv))
    {
        ipsec_sa_params->tunnel_mode = true;
    }
#ifdef SSHDIST_IKEV1
    else if (is_ikev1 == true)
    {
        /* XXX: For IKEv1 transport mode IPsec SA, substitute traffic selector
           IP addresses with local/remote IKE addresses if NAT is detected.
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
            ssh_pm_ikev2_ts_transport_mode_substitute(
                    qm->local_ts,
                    p1->ike_sa->server->
                    ip_address,
                    NULL);
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
            ssh_pm_ikev2_ts_transport_mode_substitute(
                    qm->remote_ts,
                    p1->ike_sa->remote_ip,
                    NULL);*/
    }
#endif /* SSHDIST_IKEV1 */

    ipsec_sa_endpoints->local_port = SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa);
    ipsec_sa_endpoints->remote_port = p1->ike_sa->remote_port;
    ipsec_sa_endpoints->natt = false;

    /* XXX
    if (qm->non_first_fragments_also != 0)
    {
        ipsec_sa_params->stateful_fragment_check = true;
    } */

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
    if (p1->ike_sa->flags & (SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT
                           | SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT))
    {
        SshIpAddrStruct natt_loa;
        SshIpAddrStruct natt_roa;

        /* Enable NAT-T for transform. */
        ipsec_sa_endpoints->natt = true;


        /* Set the original addresses for transport mode NAT-T.

           Note that for now the original addresses are not set for
           IKEv1 and the will perform full checksum recalculation
           for such transforms.
        */
        ssh_ikev2_ipsec_get_natt_oa(ed, &natt_loa, &natt_roa);

        in_addr_convert_from_sshipaddr(
                &ipsec_sa_params->natt_local_original_address,
                &natt_loa);
        in_addr_convert_from_sshipaddr(
                &ipsec_sa_params->natt_remote_original_address,
                &natt_roa);

        /* Enable NAT-T keepalives if this end is behind NAT. */
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
        {
            ipsec_sa_endpoints->natt_keepalive = true;
        }

        /* Mark whether the local or remote ends are behind NAT. */
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
        {
            ipsec_sa_endpoints->natt_local_nat = true;
        }

        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
        {
            ipsec_sa_endpoints->natt_remote_nat = true;
        }
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

    ipsec_sa_params->ipproto = ipproto;

    /* Set df-bit policy. */
    if (qm->rule->flags & SSH_PM_RULE_DF_SET)
    {
        ipsec_sa_params->dont_fragment_bit_policy =
            IPSEC_SA_DONT_FRAGMENT_BIT_SET;
    }
    else if (qm->rule->flags & SSH_PM_RULE_DF_CLEAR)
    {
        ipsec_sa_params->dont_fragment_bit_policy =
            IPSEC_SA_DONT_FRAGMENT_BIT_CLEAR;
    }
    else
    {
        ipsec_sa_params->dont_fragment_bit_policy =
            IPSEC_SA_DONT_FRAGMENT_BIT_UNTOUCH;
    }

    /* Set the peer IP addresses and interface number. */
    in_addr_convert_from_sshipaddr(
            &ipsec_sa_endpoints->remote_address,
            p1->ike_sa->remote_ip);
    in_addr_convert_from_sshipaddr(
            &ipsec_sa_endpoints->local_address,
            p1->ike_sa->server->ip_address);

    ipsec_sa_params->rule_id = qm->rule->rule_id;

    /* Set local lifetimes. */
    ipsec_sa_calculate_lifetimes(
            p1,
            ed,
            tunnel,
            initiator,
            &ipsec_sa_params->life_seconds,
            &ipsec_sa_params->life_bytes);

    {
        SshIkev2PayloadTransform trans;

        /* D-H */
        ipsec_sa_params->dh_algorithm_id = TRANSFORMID_D_H_NONE;

        trans = ed->ipsec_ed->ipsec_sa_transforms[
                        SSH_IKEV2_TRANSFORM_TYPE_D_H];
        if (trans != NULL)
        {
            /* Just record the group PFS was made on. */
            ipsec_sa_params->dh_algorithm_id =
                idtransformer_id_from_ikev2_dh_id(
                        trans->id);
            qm->dh_group = trans->id;
        }

        /* ESN */
        trans = ed->ipsec_ed->ipsec_sa_transforms[
                        SSH_IKEV2_TRANSFORM_TYPE_ESN];
        if (trans != NULL)
        {
            if (trans->id == SSH_IKEV2_TRANSFORM_ESN_ESN)
                ipsec_sa_params->esn = true;
        }
    }

#ifdef SSHDIST_IKEV1
    if (is_ikev1 == true)
    {
        /* Disable DPD if remote does not support it */
        if (!(p1->compat_flags & SSH_PM_COMPAT_REMOTE_DPD))
            dpd_enabled = false;
    }
#endif /* SSHDIST_IKEV1 */

#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
    /* Disable DPD for SCTP multihomed SA's as the SCTP protocol takes
       care of liveliness checking, and DPD will not work correctly in
       this case anyway */
    if (qm->rule->flags & SSH_PM_RULE_MULTIHOME)
        dpd_enabled = false;
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
    if (tunnel->vip != NULL && tunnel == qm->rule->side_to.tunnel)
    {
        /* Take a reference to the vip object for this transform. */
        ssh_pm_virtual_ip_take_ref(pm, tunnel);

        /* Set IKE peer handle to vip object. */
        ssh_pm_virtual_ip_set_peer(pm, tunnel, qm->peer_handle);

        /* Mark that VIP reference should be deleted on installation error. */
        qm->delete_vip_ref_on_error = 1;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

    qm->ipsec_sa_params.peer_handle = qm->peer_handle;

    qm->ipsec_sa_params.rekey = qm->rekey;
    qm->ipsec_sa_params.rekeyed_inbound_spi = qm->old_inbound_spi;

    if (dpd_enabled == true)
    {
        qm->ipsec_sa_params.idle_timeout_threshold_seconds =
            tunnel->idle_timeout;
        qm->ipsec_sa_params.idle_event_interval_seconds = 0;
    }
    else
    {
        qm->ipsec_sa_params.idle_timeout_threshold_seconds = 0;
        qm->ipsec_sa_params.idle_event_interval_seconds = 0;
    }
}

static bool
pm_ipsec_sa_install(
        SshPm pm,
        SshPmQm qm,
        struct IPsecSaParams *ipsec_sa_params,
        struct IPsecSaEndpoints *ipsec_sa_endpoints,
        struct IPsecSaKeyMaterial *ipsec_sa_keymaterial,
        const struct IPSelectorGroup *selector_group)
{
    bool installed;

    /* Check for simultaneous IPsec SA rekey. */
    if (ipsec_sa_params->ikev1_sa == false &&
        qm->rekey &&
        qm->simultaneous_rekey)
    {
        if (qm->initiator)
        {
            if (ssh_pm_qm_simultaneous_rekey_decide_loser(pm, qm) == true)
            {
                ipsec_sa_initiator_set_simultaneous_lost(
                        pm->ipsec_control,
                        ipsec_sa_params->inbound_spi);
            }
            else
            {
                ipsec_sa_initiator_set_simultaneous_won(
                        pm->ipsec_control,
                        ipsec_sa_params->inbound_spi);
            }
        }
        else
        {
                ipsec_sa_responder_set_simultaneous_rekey(
                        pm->ipsec_control,
                        ipsec_sa_params->inbound_spi,
                        qm->simultaneous_inbound_spi);
        }
    }

    installed =
        ipsec_sa_install(
                pm->ipsec_control,
                ipsec_sa_params,
                ipsec_sa_endpoints,
                ipsec_sa_keymaterial,
                selector_group);

    return installed;
}

/* This is the IKE library side endpoint to SA Installation */
SshOperationHandle
ssh_pm_ipsec_sa_install(SshSADHandle sad_handle,
                        SshIkev2ExchangeData ed,
                        SshIkev2SadIPsecSaInstallCB reply_callback,
                        void *reply_callback_context)
{
    SshPm pm = sad_handle->pm;
    SshPmQm qm = ed->application_context;
    SshPmP1 p1 = (SshPmP1)ed->ike_sa;
    bool installed;
    struct IPSelectorGroup *selector_group = NULL;
    SshInetIPProtocolID ipproto = SSH_IPPROTO_IPV6NONXT;
    uint32_t outbound_spi = 0;

    SSH_DEBUG(SSH_D_MIDSTART, ("[qm %p] SA installation", qm));

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("[qm %p] Failed to install IPsec SA since pm is not active.",
                 qm));

        (*reply_callback)(
                SSH_IKEV2_ERROR_SUSPENDED,
                reply_callback_context);

        return NULL;
    }

    /* Check the case of responder IKEv1 negotiations where the IKE SA has
       been deleted (ed->application_context is cleared). */
    if (qm == NULL)
    {
        (*reply_callback)(SSH_IKEV2_ERROR_OK, reply_callback_context);
        return NULL;
    }

    SSH_PM_ASSERT_PM(pm);
    SSH_PM_ASSERT_QM(qm);
    SSH_PM_ASSERT_P1(p1);
    SSH_ASSERT(qm->tunnel != NULL);

    /* DPD should never end up here. */
    SSH_ASSERT(qm->dpd == 0);
    qm->p1 = p1;

    /* Get outbound SPI. */
    outbound_spi = ed->ipsec_ed->spi_outbound;

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
        SSH_DEBUG(SSH_D_ERROR, ("[qm %p] PM is going down", qm));
        qm->error = SSH_IKEV2_ERROR_GOING_DOWN;
        goto error;
    }

    /* We'll have to check that the tunnel used for P1 still exists.
       It may have disappeared during reconfiguration. */
    if (ssh_pm_tunnel_get_by_id(pm, p1->tunnel_id) == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR, ("[qm %p] tunnel has disappeared", qm));
        qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;

        /* Mark the P1 to be unusable and to be deleted really soon. */
        p1->tunnel_id = SSH_IPSEC_INVALID_INDEX;
        p1->unusable = 1;
        p1->expire_time = monotonic_time_get();
        goto error;
    }

    /* Parse the notify payloads received from the peer's previous packet. */
#ifdef SSHDIST_IKEV1
    /* IKEv1 fallback code may have added notify payloads that need to be
       handled here before IPsec SA installation. */
#endif /* SSHDIST_IKEV1 */
    ssh_pm_ike_parse_notify_payloads(ed, qm);

    /* Replace the qm->{local,remote}_ts with proper narrowed values */
    if (qm->local_ts)
      ssh_ikev2_ts_free(sad_handle, qm->local_ts);
    if (qm->remote_ts)
      ssh_ikev2_ts_free(sad_handle, qm->remote_ts);

    qm->local_ts = qm->ed->ipsec_ed->ts_local;
    qm->remote_ts = qm->ed->ipsec_ed->ts_remote;
    ssh_ikev2_ts_take_ref(sad_handle, qm->local_ts);
    ssh_ikev2_ts_take_ref(sad_handle, qm->remote_ts);

    if (qm->transport_sent && !qm->transport_recv)
    {
        /* Responder did not select transport mode */
        if (!qm->tunnel_accepted)
        {
            /* Policy does not allow fallback to tunnel mode */
            SSH_DEBUG(SSH_D_FAIL,
                      ("[qm %p] Transport mode required but was not accepted "
                       "by the peer, failing negotiation",
                       qm));
            qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
            goto error;
        }
    }

#ifdef SSHDIST_IPSEC_MOBIKE
    /* Check if negotiation was initiated with MOBIKE but finished with MOBIKE
       disabled. In this case the negotiation may have used multiple addresses
       and here the IKE SA must be updated before installing the IPsec SA. */
    if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE)
        && ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
        && ed->multiple_addresses_used)
    {
        uint32_t natt_flags;

        SSH_DEBUG(SSH_D_LOWOK,
                  ("[qm %p] IPsec SA negotiation was started with "
                   "MOBIKE enabled, finished with MOBIKE disabled and "
                   "used multiple addresses",
                   qm));

        /* Get the NAT-T status of the current exchange. */
        (void)ssh_pm_mobike_get_exchange_natt_flags(p1, ed, &natt_flags);

        if (!ssh_pm_mobike_update_p1_addresses(pm, p1, ed->server,
                                               ed->remote_ip, ed->remote_port,
                                               natt_flags))
        {
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("[qm %p] Failed to update IKE SA addresses", qm));
            goto error;
        }
    }
#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
    if (p1->ike_sa->flags & (SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT
                             | SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT))
    {
        SshIkev2PayloadID remote_id = NULL;

        /* Get the identity of the IKE peer. */
        if (p1->remote_id != NULL)
        {
            remote_id = p1->remote_id;
        }
        else if (ed->ike_ed != NULL)
        {
            if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
              remote_id = ed->ike_ed->id_r;
            else
              remote_id = ed->ike_ed->id_i;
        }

        if (remote_id == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("[qm %p] No remote ID available", qm));
            qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
            goto error;
        }
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

    switch (ed->ipsec_ed->ipsec_sa_protocol)
    {
        case SSH_IKEV2_PROTOCOL_ID_ESP:
            ipproto = SSH_IPPROTO_ESP;
            break;
        case SSH_IKEV2_PROTOCOL_ID_AH:
        default:
            SSH_DEBUG(SSH_D_ERROR,
            ("Trying to install protocol that is not ESP"));
            return false;
    }
    if (ipsec_sa_handle_peer(pm, qm) != SSH_IKEV2_ERROR_OK)
    {
        qm->error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    {
        struct IPsecSaEndpoints *ipsec_sa_endpoints = &qm->ipsec_sa_endpoints;
        uint32_t found_spi;

        /* Check that outbound SPI doesn't exist. */
        found_spi =
            ipsec_sa_find_by_outbound_spi(
                    pm->ipsec_control,
                    true,
                    outbound_spi,
                    ipproto,
                    &ipsec_sa_endpoints->remote_address,
                    ipsec_sa_endpoints->remote_port);

        if (found_spi != 0)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Existing outbound SPI %@-%08lx already linked to "
                     "inbound SPI %@-%08lx.",
                     ssh_ipproto_render, ipproto,
                     outbound_spi,
                     ssh_ipproto_render, ipproto,
                     found_spi));

            qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
            goto error;
        }
    }

    ipsec_sa_configure_params(pm, qm, ed, outbound_spi, ipproto);

    if (pm_ipsec_sa_enc_key_material_size(
            pm,
            ed->ipsec_ed->ipsec_sa_transforms,
            &qm->ipsec_sa_keymaterial.encryption_keymaterial_len) != true)
    {
        qm->error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    if (pm_ipsec_sa_mac_key_material_size(
            pm,
            ed->ipsec_ed->ipsec_sa_transforms,
            &qm->ipsec_sa_keymaterial.integrity_keymaterial_len) != true)
    {
        qm->error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    if (pm_ipsec_fill_keymaterials(ed, qm) != true)
    {
        qm->error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    selector_group =
        ssh_pm_create_ip_selector_group(
                qm->local_ts,
                qm->remote_ts);
    if (selector_group == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("[qm %p] IPsec SA install failed, "
                 "IPSelectorGroup allocation failed", qm));

        qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    /** Create transform. */
    SSH_DEBUG(SSH_D_LOWSTART, ("[qm %p] Installing IPsec SA.", qm));

    installed =
        pm_ipsec_sa_install(
                pm,
                qm,
                &qm->ipsec_sa_params,
                &qm->ipsec_sa_endpoints,
                &qm->ipsec_sa_keymaterial,
                selector_group);

    if (installed == true)
    {
        SshPmPeer peer;
        peer = ssh_pm_peer_by_handle(pm, qm->ipsec_sa_params.peer_handle);
        SSH_ASSERT(peer != NULL);

        /* Increment the child SA counter for IKE SA's. */
        peer->num_child_sas++;

        qm->allocated_inbound_spi = 0;

        SSH_APE_MARK(1, ("IPsec SA up"));
    }
    else
    {
        /** Failed. Do not clear qm->spis here, as failed state will use
            them and remove the allocated SPI's from pm->inbound_spis. */
        SSH_DEBUG(SSH_D_FAIL, ("[qm %p] IPsec SA install failed", qm));
        qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    /* Notify unknown SPI handler about a new inbound SA. */
    ssh_pm_new_inbound_spi(
            pm,
            qm->p1->ike_sa->server->ip_address,
            qm->p1->ike_sa->remote_ip,
            qm->ipsec_sa_params.ipproto,
            qm->ipsec_sa_params.inbound_spi,
            qm->tunnel);


    /* We are finished.  Let's signal our Quick-Mode negotiation thread
       and we are done. */
    SSH_DEBUG(SSH_D_LOWOK,
              ("[qm %p] Waking Quick-Mode thread: error %d", qm, qm->error));

    qm->sa_handler_done = 1;
    if (qm->initiator)
        ssh_fsm_continue(&qm->thread);

    if (selector_group != NULL)
    {
        ssh_pm_free_selector_group(selector_group);
    }

    (*reply_callback)(qm->error, reply_callback_context);
    return NULL;


    /* Error handling. */
error:

    /*
      Notify peer (if possible) in a delayed manner. The delete
      notification will be sent after the IKE SA done notification
      is received from the IKE library.
    */
    if (qm->p1 != NULL && qm->ed != NULL)
    {
        SSH_PM_ASSERT_ED(qm->ed);
        if (qm->ipsec_sa_params.inbound_spi != 0)
        {
            SSH_DEBUG(SSH_D_HIGHOK,
                      ("[qm %p] Requesting delete notification for "
                       "SPI %@-%08lx",
                       qm,
                       ssh_ipproto_render, qm->ipsec_sa_params.ipproto,
                       qm->ipsec_sa_params.inbound_spi));
            /* XXX: possibly remove pm */
            ssh_pm_request_ipsec_delete_notification(
                    pm,
                    qm->p1,
                    qm->ipsec_sa_params.ipproto,
                    qm->ipsec_sa_params.inbound_spi);
        }
    }

    /* Release peer reference taken for the IPsec SA that was never
       installed. */
    if (qm->delete_peer_ref_on_error)
    {
        qm->delete_peer_ref_on_error = 0;
        if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
            ssh_pm_peer_handle_destroy(pm, qm->peer_handle);
    }

    /* We are finished.  Let's signal our Quick-Mode negotiation thread
       and we are done. */
    SSH_DEBUG(SSH_D_LOWOK,
              ("[qm %p] Waking Quick-Mode thread: error %d", qm, qm->error));

    qm->sa_handler_done = 1;
    if (qm->initiator)
        ssh_fsm_continue(&qm->thread);

    if (selector_group != NULL)
    {
        ssh_pm_free_selector_group(selector_group);
    }

    (*reply_callback)(qm->error, reply_callback_context);
    return NULL;
}

static void
pm_ipsec_sa_format(SshPm pm, SshPmP1 p1, SshPmQm qm, SshIkev2ExchangeData ed)
{
    SshIkev2PayloadTransform trans;
    char keysizebuf[8] = {0};
    size_t cipher_key_size = 0;
    char buf[128];
    SshPmCipher cipher = NULL;
    SshPmMac mac = NULL;

    struct IPsecSaParams *ipsec_sa_params = &qm->ipsec_sa_params;
    struct IPsecSaEndpoints *ipsec_sa_endpoints = &qm->ipsec_sa_endpoints;

    /* ENCR */
    if ((trans =
         ed->ipsec_ed->ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR])
        != NULL)
    {
        SSH_VERIFY(
                (cipher = ssh_pm_ipsec_cipher_by_id(pm, trans->id)) != NULL);

        if (trans->transform_attribute & 0x800e0000)
        {
            cipher_key_size = (trans->transform_attribute & 0xffff) / 8;
            ssh_snprintf(keysizebuf, sizeof(keysizebuf), "/%u",
                         (unsigned int) (cipher_key_size * 8));
        }
    }

    /* Integrity */
    trans = ed->ipsec_ed->ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG];
    if (trans != NULL && trans->id != SSH_IKEV2_TRANSFORM_AUTH_NONE)
    {
        SSH_VERIFY((mac = ssh_pm_ipsec_mac_by_id(pm, trans->id)) != NULL);
    }

    buf[0] = '\0';

    if (qm->rekey)
        strcat(buf, ", rekey");

    if (qm->initiator)
    {
        if (qm->tunnel->flags & SSH_PM_T_PER_PORT_SA)
            strcat(buf, ", perport");
        else if (qm->tunnel->flags & SSH_PM_T_PER_HOST_SA)
            strcat(buf, ", perhost");
    }

    /* Encapsulation mode. */
    if (ipsec_sa_endpoints->natt == true)
    {
        if (ipsec_sa_params->tunnel_mode == true)
            strcat(buf, ", NAT-T, tunnel");
        else
            strcat(buf, ", NAT-T transport");
    }
    else
    {
        if (ipsec_sa_params->tunnel_mode == true)
            strcat(buf, ", tunnel");
        else
            strcat(buf, ", transport");
    }

    if (qm->auto_start)
      strcat(buf, ", auto");

    if (ipsec_sa_params->esn == true)
        strcat(buf, ", seq-64");

    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "");
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "IPsec SA [%s%s] negotiation completed:",
                  qm->initiator ? "Initiator" : "Responder",
                  buf);

    if (qm->dh_group)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                      "");
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                      "  PFS using Diffie-Hellman group %u (%u bits)",
                      qm->dh_group,
                      ssh_pm_dh_group_size(pm, qm->dh_group));
    }

    if (!qm->rekey)
      ssh_pm_log_p1(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL, p1, false);

    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "  Local Traffic Selector  %@",
                  ssh_ikev2_ts_render, qm->ed->ipsec_ed->ts_local);
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "  Remote Traffic Selector %@",
                  ssh_ikev2_ts_render, qm->ed->ipsec_ed->ts_remote);
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "  Routing Instance  %s (%d)",
                  qm->tunnel->routing_instance_name,
                  qm->tunnel->routing_instance_id);
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "");

    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "  Inbound SPI:      | Outbound SPI: | Algorithm:");


    if (ipsec_sa_params->ipproto == SSH_IPPROTO_ESP)
    {
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                      "  ESP    [%08lx] | [%08lx]    | %s%s - %s",
                      (unsigned long)
                      ipsec_sa_params->inbound_spi,
                      (unsigned long)
                      ipsec_sa_params->outbound_spi,
                      cipher ? cipher->name : "none", keysizebuf,
                      mac ? mac->name : "none");
    }
    else
    {
        ssh_log_event(
                SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  AH     [%08lx] | [%08lx]    | %s",
                (unsigned long)
                ipsec_sa_params->inbound_spi,
                (unsigned long)
                ipsec_sa_params->outbound_spi,
                mac ? mac->name : "none");
    }

    /* Print lifetimes */
    if (ipsec_sa_params->life_bytes && ipsec_sa_params->life_seconds)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_INFORMATIONAL,
                "  Local Lifetime: %u bytes, %u seconds",
                (unsigned int) ipsec_sa_params->life_bytes,
                (unsigned int) ipsec_sa_params->life_seconds);
    }
    else if (ipsec_sa_params->life_seconds)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_INFORMATIONAL,
                "  Local Lifetime: %u seconds",
                (unsigned int) ipsec_sa_params->life_seconds);
    }
    else if (ipsec_sa_params->life_bytes)
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_INFORMATIONAL,
                "  Local Lifetime: %u bytes",
                (unsigned int) ipsec_sa_params->life_bytes);
    }
    else
    {
        ssh_log_event(
                SSH_LOGFACILITY_DAEMON,
                SSH_LOG_INFORMATIONAL,
                "  Local Lifetime: infinite");
    }
    /* Audit event of the inbound */
    {
        unsigned char spi_buf[4];
        SSH_PUT_32BIT(spi_buf, ipsec_sa_params->inbound_spi);
        ssh_pm_audit_event(
                pm,
                SSH_PM_AUDIT_POLICY,
                SSH_AUDIT_NOTICE,
                SSH_AUDIT_TXT,
                ipsec_sa_params->rekeyed_inbound_spi != 0 ?
                "Rekeyed IPsec SA installed" : "IPsec SA installed",
                SSH_AUDIT_TXT,
                ipsec_sa_params->ipproto == SSH_IPPROTO_ESP ? "esp":"",
                SSH_AUDIT_SPI, spi_buf, sizeof(spi_buf),
                SSH_AUDIT_ARGUMENT_END);
    }
}

void
ssh_pm_ipsec_sa_done(SshSADHandle sad_handle,
                     SshIkev2ExchangeData ed,
                     SshIkev2Error status)
{
    SshPm pm = sad_handle->pm;
    SshPmQm qm = ed->application_context;
    SshPmQmStruct qm_struct;
    SshPmP1 p1 = (SshPmP1)ed->ike_sa;

    SSH_DEBUG(SSH_D_LOWSTART, ("IPsec SA done for qm=%p, status is %d",
                               qm, status));

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
    if (!qm || !qm->rule || !(qm->rule->flags & SSH_PM_RULE_CFGMODE_RULES))
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
      pm->stats.num_qm_done++;

    /* Update the auto-start status for responder negotiations. */
    if (qm && !qm->initiator)
      ssh_pm_qm_update_auto_start_status(pm, qm);

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
    SSH_ASSERT(p1 != NULL);
    if (p1->auth_cert)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing P1 auth cert reference"));
        ssh_cm_cert_remove_reference(p1->auth_cert);
        p1->auth_cert = NULL;
    }

    if (p1->auth_ca_cert)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing P1 auth ca cert reference"));
        ssh_cm_cert_remove_reference(p1->auth_ca_cert);
        p1->auth_ca_cert = NULL;
    }
#else /* SSHDIST_CERT */















#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */







    /* 'qm' may be NULL for IKEv1 negotiations if the responder side
       Quick-Mode negotiation failed before SPI allocation. In this case,
       fabricate a 'qm' for clearer logging messages. */
    if (qm == NULL)
    {



        if (status == SSH_IKEV2_ERROR_OK)
          status = SSH_IKEV2_ERROR_INVALID_ARGUMENT;

        memset(&qm_struct, 0, sizeof(qm_struct));
        qm_struct.p1 = p1;
        qm = &qm_struct;

        SSH_DEBUG(SSH_D_FAIL, ("IPSEC SA negotiation failed: %d", status));

        pm->stats.num_qm_failed++;

        qm->error = status;
        ssh_pm_log_qm_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            qm, "failed");
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                      "  Message: %s (%d)",
                      ssh_pm_qm_error_to_string(status), status);

        ssh_log_event(
                SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "IPsec SA negotiations: %u done, %u successful, %u failed",
                (unsigned int) pm->stats.num_qm_done,
                (unsigned int) (pm->stats.num_qm_done -
                                pm->stats.num_qm_failed),
                (unsigned int) pm->stats.num_qm_failed);
        return;
    }

    SSH_PM_ASSERT_QM(qm);
    qm->ike_done = 1;

#ifdef SSHDIST_IKEV1
    if ((ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED)
        && qm->initiator
        && !qm->aborted
        && qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1
        && status == SSH_IKEV2_ERROR_SA_UNUSABLE)
    {
        SshPmPeer peer;
        uint32_t old_peer_handle;

        /* Detach this QM from P1 */
        PM_IKE_ASYNC_CALL_COMPLETE(qm->p1->ike_sa, ed);

        qm->p1->unusable = 1;

        /* For new IPsec SA negotiations update qm->peer_handle with the
           peer handle of this p1 that is next going to be replaced with
           a new p1. For rekeys and dpd we do not want to update the
           peer_handle. */
        if (!qm->rekey && !qm->dpd)
        {
            old_peer_handle = qm->peer_handle;
            qm->peer_handle = ssh_pm_peer_handle_by_p1(pm, qm->p1);

            /* If qm->peer_handle changed then take a reference to the
               new peer_handle and free the reference to the old peer
               handle. */
            if (qm->peer_handle != old_peer_handle)
            {
                if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
                  ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
                if (old_peer_handle != SSH_IPSEC_INVALID_INDEX)
                  ssh_pm_peer_handle_destroy(pm, old_peer_handle);
            }
        }

        /* Detach IKE SA from IKE peer. */
        do
        {
            /* There might be multiple IKE peers pointing to same IKE SA. */
            peer = ssh_pm_peer_by_p1(pm, qm->p1);
            if (peer)
              ssh_pm_peer_update_p1(pm, peer, NULL);
        }
        while (peer != NULL);

        /* Reset qm->p1_tunnel before stepping back to
           ssh_pm_st_qm_i_n_select_p1. */
        if (qm->p1_tunnel)
        {
            SSH_PM_TUNNEL_DESTROY(pm, qm->p1_tunnel);
            qm->p1_tunnel = NULL;
        }

        /* Rekey for IKE SA is required to complete this QM.
           Perform it now. */
        SSH_DEBUG(SSH_D_FAIL, ("Quick-Mode failed because of unusable "
                               "IKE SA, reselecting Phase-I, qm=%p, "
                               "p1=%p", qm, qm->p1));

        qm->error = SSH_IKEV2_ERROR_USE_IKEV1;

        ssh_fsm_set_next(&qm->thread, ssh_pm_st_qm_i_n_select_p1);
        ssh_fsm_continue(&qm->thread);

        /* Decrement the statistics counter */
        pm->stats.num_qm_done--;
        return;
    }
#endif /* SSHDIST_IKEV1 */

    /* Negotiation or SA handler failed. */
    if (status != SSH_IKEV2_ERROR_OK || qm->error != SSH_IKEV2_ERROR_OK)
    {
        /* Do not clear qm->error in case SA handler has failed. */
        if (status == SSH_IKEV2_ERROR_OK)
          status = qm->error;

        SSH_DEBUG(SSH_D_FAIL, ("IPSEC SA negotiation failed: %d", status));

        qm->sa_handler_done = 1;
        qm->error = status;

        pm->stats.num_qm_failed++;

        ssh_pm_log_qm_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            qm, "failed");
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                      "  Message: %s (%d)",
                      ssh_pm_qm_error_to_string(status), status);

        if (qm->failure_mask || qm->ike_failure_mask)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                          "  Reason:");
            if (qm->failure_mask)
              ssh_pm_log_rule_selection_failure(SSH_LOGFACILITY_AUTH,
                                                SSH_LOG_INFORMATIONAL,
                                                p1,
                                                qm->failure_mask);

            if (qm->ike_failure_mask)
              ssh_pm_log_ike_sa_selection_failure(SSH_LOGFACILITY_AUTH,
                                                  SSH_LOG_INFORMATIONAL,
                                                  p1,
                                                  qm->ike_failure_mask);
        }
    }
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
    else if (qm->rule && (qm->rule->flags & SSH_PM_RULE_CFGMODE_RULES))
    {
        qm->sa_handler_done = 1;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
    else /* Successful negotiation. */
    {
        SSH_ASSERT(qm->sa_handler_done == 1);

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
        if (p1->cfgmode_client != NULL)
        {
            pm_ras_radius_acct_start(pm, p1->cfgmode_client);
        }
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

        /* Indicate that the SA has created/rekeyed. */
        if (qm->rekey)
          ssh_pm_ipsec_sa_event_rekeyed(pm, qm);
        else
          ssh_pm_ipsec_sa_event_created(pm, qm);

        /* Zeroize SPI that should be taken into use by the SA.
           Otherwise the SPI will be freed when the Quick-mode is freed. */
        qm->allocated_inbound_spi = 0;

        /* Format SA options and print preamble for SA's */
        pm_ipsec_sa_format(pm, p1, qm, ed);
    }

    /* Handle delayed delete notifications. */
    ssh_pm_send_ipsec_delete_notification_requests(pm, p1);

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
    if (!qm || !qm->rule || !(qm->rule->flags & SSH_PM_RULE_CFGMODE_RULES))
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "IPsec SA negotiations: %u done, %u successful, %u failed",
                    (unsigned int) pm->stats.num_qm_done,
                    (unsigned int) (pm->stats.num_qm_done -
                                    pm->stats.num_qm_failed),
                    (unsigned int) pm->stats.num_qm_failed);
}


/* Set endpoint for tunnels. Moves the IKE SA and all its children to
   use ip_address:port as outbound destination. This is called when NAT
   mappings change */
void
ssh_pm_ipsec_sa_update(SshSADHandle sad_handle,
                       SshIkev2ExchangeData ed,
                       SshIpAddr ip_address, uint16_t port)
{
    SshPm pm = sad_handle->pm;
    SshPmP1 p1 = (SshPmP1)ed->ike_sa;
    SshPmPeer peer;





#ifdef SSHDIST_IPSEC_MOBIKE
    if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Mobike enabled, ignoring IPsec SA update for IKE SA %p",
                   p1->ike_sa));
        return;
    }
#endif /* SSHDIST_IPSEC_MOBIKE */

    SSH_DEBUG(SSH_D_LOWOK, ("IKE SA %p, status %s, ip %@, port %d",
                            p1, p1->done ? "done" : "negotiating",
                            ssh_ipaddr_render, ip_address, port));

    if (!SSH_PM_P1_USABLE(p1) ||
        ssh_pm_tunnel_get_by_id(pm, p1->tunnel_id) == NULL)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA update ignored, IKE SA %p unusable.",
                                p1->ike_sa));
        return;
    }

    if (p1->done)
    {
        /* Remove p1 from ike_sa_hash table */
        ssh_pm_ike_sa_hash_remove(pm, p1);

        /* Update IKE peer information. */
        ssh_pm_peer_p1_update_address(pm, p1, ip_address, port,
                                      p1->ike_sa->server->ip_address,
                                      SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa));
    }

    /* Update peer address and port to p1 */
    *p1->ike_sa->remote_ip = *ip_address;
    p1->ike_sa->remote_port = port;

    if (p1->done)
    {
        /* Insert p1 back to ike_sa_hash table */
        ssh_pm_ike_sa_hash_insert(pm, p1);

        /* Indicate that IKE SA has been updated. */
        ssh_pm_ike_sa_event_updated(pm, p1);

        /* Assert that port float is done and atleast one end is behind NAT. */
        SSH_ASSERT(
                p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE);
        SSH_ASSERT(
                p1->ike_sa->flags &
                (SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT
                 | SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT));

        /* Update address and port info to child SAs */
        for (peer = ssh_pm_peer_by_ike_sa_handle(pm, SSH_PM_IKE_SA_INDEX(p1));
             peer != NULL;
             peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer))
        {
            SSH_ASSERT(peer != NULL);
            SSH_ASSERT(peer->peer_handle != SSH_IPSEC_INVALID_INDEX);

            /* Indicate that IPsec SAs have been updated. */
            ssh_pm_ipsec_sa_event_peer_updated(pm, peer, true, false);

        }
    }
}
