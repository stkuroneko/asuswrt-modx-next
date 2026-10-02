/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKE SPD policy calls.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmIke"











SshIkev2Error
pm_get_ipsec_transform_proposal(
        SshPm pm,
        SshPmTunnel tunnel,
        uint32_t inbound_spi,
        SshIkev2PayloadSA *sa_p)
{
  const struct IPsecSaParams *ipsec_sa_params;
  SshIkev2PayloadSA ipsec_sa_payload;
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  const int proposal_index = 0;

  ipsec_sa_payload = ssh_ikev2_sa_allocate(pm->sad_handle);
  if (ipsec_sa_payload == NULL)
    {
      status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      ipsec_sa_params = ipsec_sa_get_params(pm->ipsec_control, inbound_spi);
      if (ipsec_sa_params == NULL)
        {
          status = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
        }
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      SshIkev2TransformID encr;
      int keylen;

      encr =
          idtransformer_id_to_ikev2_encr_id(
                  ipsec_sa_params->encryption_algorithm_id,
                  &keylen);

      status =
          ssh_ikev2_sa_add(
                  ipsec_sa_payload,
                  proposal_index,
                  SSH_IKEV2_TRANSFORM_TYPE_ENCR,
                  encr,
                  SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(keylen));
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      if (ipsec_sa_params->integrity_algorithm_id != TRANSFORMID_INTEG_NONE)
        {
          SshIkev2TransformID integ;

          integ =
              idtransformer_id_to_ikev2_integ_id(
                      ipsec_sa_params->integrity_algorithm_id);

          status =
              ssh_ikev2_sa_add(
                      ipsec_sa_payload,
                      proposal_index,
                      SSH_IKEV2_TRANSFORM_TYPE_INTEG,
                      integ,
                      0);
        }
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      SshIkev2TransformID esn;

      if (ipsec_sa_params->esn == true)
        {
          esn = SSH_IKEV2_TRANSFORM_ESN_ESN;
        }
      else
        {
          esn = SSH_IKEV2_TRANSFORM_ESN_NO_ESN;
        }

        status =
            ssh_ikev2_sa_add(
                    ipsec_sa_payload,
                    proposal_index,
                    SSH_IKEV2_TRANSFORM_TYPE_ESN,
                    esn,
                    0);

    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      if (ipsec_sa_params->dh_algorithm_id == TRANSFORMID_D_H_NONE)
        {
          if (ipsec_sa_params->rekey == false)
            {
              /* First rekey; try to add pfs groups. */
              SshPmDHGroup dhgroup;
              int i;

              for (i = 0; status == SSH_IKEV2_ERROR_OK; i++)
                {
                  dhgroup = ssh_pm_tunnel_dh_group(tunnel, i, true);
                  if (dhgroup == NULL)
                    {
                      break;
                    }

                  status =
                      ssh_ikev2_sa_add(
                              ipsec_sa_payload,
                              proposal_index,
                              SSH_IKEV2_TRANSFORM_TYPE_D_H,
                              dhgroup->group_desc,
                              0);
                }
            }
        }
      else
        {
          SshIkev2TransformID dhgroup;

          dhgroup =
              idtransformer_id_to_ikev2_dh_id(
                      ipsec_sa_params->dh_algorithm_id);

          status =
              ssh_ikev2_sa_add(
                      ipsec_sa_payload,
                      proposal_index,
                      SSH_IKEV2_TRANSFORM_TYPE_D_H,
                      dhgroup,
                      0);
        }
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      SshIkev2ProtocolIdentifiers proto_id = SSH_IKEV2_PROTOCOL_ID_NONE;

      if (ipsec_sa_params->ipproto == SSH_IPPROTO_ESP)
        {
          proto_id = SSH_IKEV2_PROTOCOL_ID_ESP;
        }
      else
      if (ipsec_sa_params->ipproto == SSH_IPPROTO_AH)
        {
          proto_id = SSH_IKEV2_PROTOCOL_ID_AH;
        }

      ipsec_sa_payload->protocol_id[proposal_index] = proto_id;
    }

  *sa_p = ipsec_sa_payload;

  return status;
}


/*--------------------------------------------------------------------*/
/*       Static helper functions                                      */
/*--------------------------------------------------------------------*/


/* Notify callback for ssh_ikev2_ike_sa_rekey(). */
void
pm_ike_sa_rekey_done_callback(SshSADHandle sad_handle,
                              SshIkev2Sa sa,
                              SshIkev2ExchangeData ed,
                              SshIkev2Error error)
{
    SshPmP1 old_p1 = (SshPmP1)sa;
    SshPmP1 new_p1;

    SSH_DEBUG(SSH_D_LOWOK, ("IKE SA rekey done, ike error code %s",
                            ssh_ikev2_error_to_string(error)));

    SSH_PM_ASSERT_P1(old_p1);
    old_p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] = NULL;

    /* Update old rekeyed IKE SA since it state has changed to rekeyed. */
    ssh_pm_ike_sa_event_updated(sad_handle->pm, old_p1);

    /* Send any delayed delete notifications. */
    if (error == SSH_IKEV2_ERROR_OK)
    {
        /* Send notifications with the new initiated IKE SA. */
        new_p1 = PM_IKE_SA_REKEY_NEW_P1(old_p1, true);
        if (new_p1 != NULL)
          ssh_pm_send_ipsec_delete_notification_requests(
                  sad_handle->pm, new_p1);

        /* Send notifications with the new responded IKE SA. The responded new
           IKE SA is non-NULL and has delayed delete notification requests only
           in the case we are the loser of a simultaneous IKE SA rekey. */
        new_p1 = PM_IKE_SA_REKEY_NEW_P1(old_p1, false);
        if (new_p1 != NULL)
          ssh_pm_send_ipsec_delete_notification_requests(
                  sad_handle->pm, new_p1);
    }
#ifdef SSHDIST_IPSEC_MOBIKE
    /* Check if need to trigger MOBIKE address update. This is done if the
       IKE SA rekey fails with TEMPORARY_FAILURE. */
    else
    {
        ssh_pm_mobike_check_exchange(sad_handle->pm, error, (SshPmP1) sa, ed);
    }
#endif /* SSHDIST_IPSEC_MOBIKE */
}

static SshIkev2Error
pm_build_ike_sa_from_p1(SshPm pm, SshPmP1 p1,
                        SshIkev2PayloadSA *sa_payload_return)
{
    int encr_transform_id, prf_transform_id, auth_transform_id;
    SshIkev2PayloadSA ike_sa_payload = NULL;
    SshIkev2Error ike_error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    uint32_t key_size;

    *sa_payload_return = NULL;

    ike_sa_payload = ssh_ikev2_sa_allocate(pm->sad_handle);
    if (ike_sa_payload == NULL)
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

    SSH_DEBUG(SSH_D_LOWSTART, ("IKE algorithms encrypt/prf/mac %s/%s/%s",
                               p1->ike_sa->encrypt_algorithm,
                               p1->ike_sa->prf_algorithm,
                               p1->ike_sa->mac_algorithm));

    encr_transform_id = ssh_find_keyword_number(ssh_ikev2_encr_algorithms,
                                                p1->ike_sa->encrypt_algorithm);
    if (encr_transform_id == -1)
      goto error;
    key_size = (encr_transform_id >> 16);

    ike_error =
        ssh_ikev2_sa_add(
                ike_sa_payload, 0,SSH_IKEV2_TRANSFORM_TYPE_ENCR,
                (encr_transform_id & 0xffff),
                SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));
    if (ike_error != SSH_IKEV2_ERROR_OK)
      goto error;

    prf_transform_id =
        ssh_find_keyword_number(
                ssh_ikev2_prf_algorithms,
                p1->ike_sa->prf_algorithm);

    if (prf_transform_id == -1)
      goto error;

    key_size = (prf_transform_id >> 16);

    ike_error =
        ssh_ikev2_sa_add(
                ike_sa_payload, 0, SSH_IKEV2_TRANSFORM_TYPE_PRF,
                (prf_transform_id & 0xffff),
                SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));
    if (ike_error != SSH_IKEV2_ERROR_OK)
      goto error;

    if (p1->ike_sa->mac_algorithm != NULL)
    {
        auth_transform_id = ssh_find_keyword_number(ssh_ikev2_mac_algorithms,
                                                    p1->ike_sa->mac_algorithm);
        if (auth_transform_id == -1)
          goto error;

        key_size = (auth_transform_id >> 16);

        ike_error =
            ssh_ikev2_sa_add(
                    ike_sa_payload, 0,
                    SSH_IKEV2_TRANSFORM_TYPE_INTEG,
                    (auth_transform_id & 0xffff),
                    SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));
        if (ike_error != SSH_IKEV2_ERROR_OK)
          goto error;
    }
    else
    {
        /* This is allowed only with combined ciphers */
        SSH_ASSERT(ssh_cipher_is_auth_cipher(p1->ike_sa->encrypt_algorithm));
    }

    ike_error =
        ssh_ikev2_sa_add(
                ike_sa_payload, 0, SSH_IKEV2_TRANSFORM_TYPE_D_H,
                p1->dh_group, 0);

    if (ike_error != SSH_IKEV2_ERROR_OK)
      goto error;

    ike_sa_payload->protocol_id[0] = SSH_IKEV2_PROTOCOL_ID_IKE;
    *sa_payload_return = ike_sa_payload;
    return SSH_IKEV2_ERROR_OK;

   error:
    SSH_ASSERT(ike_error != SSH_IKEV2_ERROR_OK);
    ssh_ikev2_sa_free(pm->sad_handle, ike_sa_payload);
    return ike_error;
}


static SshIkev2Error
ssh_pm_sa_build_ciphers_from_tunnel(SshPm pm,
                                    SshPmTunnel tunnel,
                                    SshIkev2PayloadSA sa_payload,
                                    int proposal_index,
                                    bool combined_mode,
                                    bool ike_proposal,
                                    uint32_t algorithms,
                                    uint16_t requested_key_size,
                                    int num_ciphers)
{
    int i;
    SshIkev2Error ike_error = SSH_IKEV2_ERROR_OK;
    uint32_t cipher_mask = SSH_PM_CRYPT_MASK;
    uint32_t key_size_mask;

    if (combined_mode == true)
    {
        cipher_mask = SSH_PM_COMBINED_MASK;
    }
    else
    {
        cipher_mask = ~SSH_PM_COMBINED_MASK;
    }

    if (ike_proposal)
    {
        key_size_mask = SSH_PM_ALG_IKE_SA;
    }
    else
    {
        key_size_mask = SSH_PM_ALG_IPSEC_SA;
    }

    /* Create cipher transforms. */
    for (i = 0; i < num_ciphers && ike_error == SSH_IKEV2_ERROR_OK; i++)
    {
        int transform_id;
        SshPmCipher cipher;

        if (ike_proposal)
        {
            cipher = ssh_pm_ike_cipher(pm, i, algorithms);
            transform_id = cipher->ike_encr_transform_id;
        }
        else
        {
            cipher = ssh_pm_ipsec_cipher(pm, i, algorithms);
            transform_id = cipher->esp_transform_id;
        }

        if ((cipher->mask_bits & cipher_mask) == 0)
        {
            continue;
        }

        if (ssh_pm_cipher_is_fixed_key_length(cipher))
        {
            ike_error = ssh_ikev2_sa_add(sa_payload,
                                         proposal_index,
                                         SSH_IKEV2_TRANSFORM_TYPE_ENCR,
                                         transform_id,
                                         0);
        }
        else
        {
            uint32_t min_key_size;
            uint32_t max_key_size;
            uint32_t default_key_size;
            uint32_t key_size_increment;
            uint32_t key_size;

            /* Resolve the key size to propose with this cipher for our
               tunnel. */
            ssh_pm_cipher_key_sizes(tunnel, cipher, key_size_mask,
                                    &min_key_size, &max_key_size,
                                    &key_size_increment, &default_key_size);

            SSH_ASSERT(key_size_increment > 0);
            SSH_ASSERT(((max_key_size - min_key_size) % key_size_increment)
                       == 0);

            /* If a specific cipher key size was requested, then add only this
               requested key size. */
            if (requested_key_size > 0)
            {
                /* Lookup the requested cipher key size. */
                for (key_size = min_key_size;
                     key_size <= max_key_size;
                     key_size += key_size_increment)
                {
                    if (key_size == requested_key_size)
                    {
                        /* Found it, add key size to proposal and return. */
                        SSH_DEBUG(SSH_D_MIDOK,
                                  ("Adding keysize %d to proposal",
                                   (int) requested_key_size));
                        return ssh_ikev2_sa_add(sa_payload,
                                                proposal_index,
                                                SSH_IKEV2_TRANSFORM_TYPE_ENCR,
                                                transform_id,
                                                SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE
                                                (requested_key_size));
                    }
                }

                /* Requested cipher key size was not found, return error. */
                return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
            }

            /* Add the default key size first, this is our preferred
               key size.*/
            SSH_DEBUG(SSH_D_MIDOK,
                      ("Adding keysize %d to proposal",
                       (int) default_key_size));
            ike_error = ssh_ikev2_sa_add(sa_payload,
                                         proposal_index,
                                         SSH_IKEV2_TRANSFORM_TYPE_ENCR,
                                         transform_id,
                                         SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE
                                         (default_key_size));

            for (key_size = min_key_size;
                 key_size <= max_key_size &&
                     ike_error == SSH_IKEV2_ERROR_OK;
                 key_size += key_size_increment)
            {
                if (key_size == default_key_size)
                  continue;

                SSH_DEBUG(SSH_D_MIDOK,
                          ("Adding keysize %d to proposal",
                           (int) key_size));
                ike_error =
                  ssh_ikev2_sa_add(sa_payload,
                                   proposal_index,
                                   SSH_IKEV2_TRANSFORM_TYPE_ENCR,
                                   transform_id,
                                   SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size));
            }
        }
    }

    return ike_error;
}


static SshIkev2Error
ssh_pm_sa_build_macs_from_tunnel(SshPm pm,
                                 SshPmTunnel tunnel,
                                 SshIkev2PayloadSA sa_payload,
                                 int proposal_index,
                                 bool ike_proposal,
                                 uint32_t algorithms,
                                 uint16_t requested_key_size,
                                 int num_hashes)
{
    SshIkev2Error ike_error = SSH_IKEV2_ERROR_OK;
    uint32_t key_size_mask;
    int i;

    if (ike_proposal)
    {
        key_size_mask = SSH_PM_ALG_IKE_SA;
    }
    else
    {
        key_size_mask = SSH_PM_ALG_IPSEC_SA;
    }

    /* Create mac transforms. */
    for (i = 0; i < num_hashes && ike_error == SSH_IKEV2_ERROR_OK; i++)
    {
        SshPmMac mac;
        int transform_id;

        if (ike_proposal)
        {
            mac = ssh_pm_ike_mac(pm, i, algorithms);
            transform_id = mac->ike_auth_transform_id;
        }
        else
        {
            mac = ssh_pm_ipsec_mac(pm, i, algorithms);
            transform_id = mac->ipsec_transform_id;
        }

        SSH_ASSERT(mac != NULL);

        if (ssh_pm_mac_is_fixed_key_length(mac))
        {
            SSH_ASSERT(transform_id != 0);

            ike_error = ssh_ikev2_sa_add(sa_payload,
                                         proposal_index,
                                         SSH_IKEV2_TRANSFORM_TYPE_INTEG,
                                         transform_id,
                                         0);
        }
        else
        {
            uint32_t min_key_size;
            uint32_t max_key_size;
            uint32_t default_key_size;
            uint32_t key_size_increment;
            uint32_t key_size;
            int mac_transform_id;
            uint32_t mac_transform_attribute;

            /* Resolve the key size to propose with this mac for our
               tunnel. */
            ssh_pm_mac_key_sizes(tunnel, mac, key_size_mask,
                                 &min_key_size, &max_key_size,
                                 &key_size_increment, &default_key_size);

            SSH_ASSERT(key_size_increment > 0);
            SSH_ASSERT(
                    (max_key_size - min_key_size) % key_size_increment == 0);

            /* If a specific mac key size was requested, then add only this
               requested key size. */
            if (requested_key_size > 0)
            {
                /* Lookup the requested mac key size. */
                for (key_size = min_key_size;
                     key_size <= max_key_size;
                     key_size += key_size_increment)
                {
                    if (key_size == requested_key_size)
                    {
                        /* Found it, add key size to proposal and return. */
                        SSH_DEBUG(SSH_D_MIDOK,
                                  ("Adding keysize %d to proposal",
                                   (int) key_size));

                        if (transform_id == 0)
                        {
                            mac_transform_id =
                              ssh_pm_mac_auth_id_for_keysize(mac, key_size);
                            mac_transform_attribute = 0;
                        }
                        else
                        {
                            mac_transform_id = transform_id;
                            mac_transform_attribute =
                              SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size);
                        }
                        SSH_ASSERT(mac_transform_id != 0);

                        return ssh_ikev2_sa_add(sa_payload,
                                                proposal_index,
                                                SSH_IKEV2_TRANSFORM_TYPE_INTEG,
                                                mac_transform_id,
                                                mac_transform_attribute);
                    }
                }

                /* Requested mac key size was not found, return error. */
                return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
            }

            /* Add the default key size first, this is our preferred
               key size.*/
            SSH_DEBUG(SSH_D_MIDOK,
                      ("Adding keysize %d to proposal",
                       (int) default_key_size));

            if (transform_id == 0)
            {
                if (ike_proposal)
                {
                    mac_transform_id =
                        ssh_pm_mac_ike_auth_id_for_keysize(
                                mac, default_key_size);
                    mac_transform_attribute = 0;
                }
                else
                {
                    mac_transform_id =
                      ssh_pm_mac_auth_id_for_keysize(mac, default_key_size);
                    mac_transform_attribute = 0;
                }
            }
            else
            {
                mac_transform_id = transform_id;
                mac_transform_attribute =
                  SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(default_key_size);
            }
            SSH_ASSERT(mac_transform_id != 0);

            ike_error = ssh_ikev2_sa_add(sa_payload,
                                         proposal_index,
                                         SSH_IKEV2_TRANSFORM_TYPE_INTEG,
                                         mac_transform_id,
                                         mac_transform_attribute);

            for (key_size = min_key_size;
                 key_size <= max_key_size &&
                   ike_error == SSH_IKEV2_ERROR_OK;
                 key_size += key_size_increment)
            {
                if (key_size == default_key_size)
                  continue;

                if (transform_id == 0)
                {
                    if (ike_proposal)
                    {
                        mac_transform_id =
                          ssh_pm_mac_ike_auth_id_for_keysize(mac, key_size);
                        mac_transform_attribute = 0;
                    }
                    else
                    {
                        mac_transform_id =
                          ssh_pm_mac_auth_id_for_keysize(mac, key_size);
                        mac_transform_attribute = 0;
                    }
                }
                else
                {
                    mac_transform_id = transform_id;
                    mac_transform_attribute =
                      SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(key_size);
                }

                SSH_ASSERT(mac_transform_id != 0);

                SSH_DEBUG(SSH_D_MIDOK,
                          ("Adding keysize %d to proposal",
                           (int) key_size));

                ike_error = ssh_ikev2_sa_add(sa_payload,
                                             proposal_index,
                                             SSH_IKEV2_TRANSFORM_TYPE_INTEG,
                                             mac_transform_id,
                                             mac_transform_attribute);
            }
        }
    }

    return ike_error;
}


static SshIkev2Error
ssh_pm_ike_sa_build_prfs_from_tunnel(SshIkev2PayloadSA ike_sa_payload,
                                     int proposal_index,
                                     SshPm pm,
                                     SshPmTunnel tunnel,
                                     int num_hashes)
{
    SshIkev2Error ike_error = SSH_IKEV2_ERROR_OK;
    int i;

    /* Create mac transforms. */
    for (i = 0; i < num_hashes && ike_error == SSH_IKEV2_ERROR_OK; i++)
    {
        SshPmMac mac;

        mac = ssh_pm_ike_mac(pm, i, tunnel->u.ike.algorithms);
        SSH_ASSERT(mac != NULL);

        if (ssh_pm_mac_is_fixed_key_length(mac))
        {
            SSH_ASSERT(mac->ike_prf_transform_id != 0);

            ike_error = ssh_ikev2_sa_add(ike_sa_payload,
                                         proposal_index,
                                         SSH_IKEV2_TRANSFORM_TYPE_PRF,
                                         mac->ike_prf_transform_id,
                                         0);
        }
        else
        {
            uint32_t min_key_size;
            uint32_t max_key_size;
            uint32_t default_key_size;
            uint32_t key_size_increment;
            uint32_t key_size;

            /* Resolve the key size to propose with this mac for our
               tunnel. */
            ssh_pm_mac_key_sizes(tunnel, mac, SSH_PM_ALG_IKE_SA,
                                 &min_key_size, &max_key_size,
                                 &key_size_increment, &default_key_size);

            SSH_ASSERT(key_size_increment > 0);
            SSH_ASSERT((max_key_size - min_key_size) % key_size_increment
                       == 0);

            if (mac->ike_prf_transform_id == 0)
            {
                /* There are separate IDs for different
                   keysizes. Let's follow keysizes to gather
                   the IDs. */
                SshIkev2TransformID prf_id;

                SSH_ASSERT(key_size_increment > 0);
                SSH_ASSERT((max_key_size - min_key_size)
                           % key_size_increment == 0);

                /* Add the default key size first, this is our preferred
                   key size.*/
                SSH_DEBUG(SSH_D_MIDOK,
                          ("Adding keysize %d to proposal",
                           (int) default_key_size));

                prf_id =
                    ssh_pm_mac_ike_prf_id_for_keysize(
                            mac,
                            default_key_size);
                SSH_ASSERT(prf_id != 0);

                ike_error = ssh_ikev2_sa_add(ike_sa_payload,
                                             proposal_index,
                                             SSH_IKEV2_TRANSFORM_TYPE_PRF,
                                             prf_id,
                                             0);

                for (key_size = min_key_size;
                     key_size <= max_key_size &&
                         ike_error == SSH_IKEV2_ERROR_OK;
                     key_size += key_size_increment)
                {
                    if (key_size == default_key_size)
                      continue;

                    prf_id = ssh_pm_mac_ike_prf_id_for_keysize(mac, key_size);

                    SSH_ASSERT(prf_id != 0);

                    SSH_DEBUG(SSH_D_MIDOK,
                              ("Adding keysize %d to proposal",
                               (int) key_size));

                    ike_error = ssh_ikev2_sa_add(ike_sa_payload,
                                                 proposal_index,
                                                 SSH_IKEV2_TRANSFORM_TYPE_PRF,
                                                 prf_id,
                                                 0);
                }
            }
            else
            {
                /* Add the default key size first, this is our preferred
                   key size.*/
                SSH_DEBUG(SSH_D_MIDOK,
                          ("Adding keysize %d to proposal",
                           (int) default_key_size));
                ike_error = ssh_ikev2_sa_add(ike_sa_payload, proposal_index,
                                             SSH_IKEV2_TRANSFORM_TYPE_PRF,
                                             mac->ike_prf_transform_id,
                                             SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE
                                             (default_key_size));

                for (key_size = min_key_size;
                     key_size <= max_key_size &&
                         ike_error == SSH_IKEV2_ERROR_OK;
                     key_size += key_size_increment)
                {
                    if (key_size == default_key_size)
                      continue;

                    SSH_DEBUG(SSH_D_MIDOK,
                              ("Adding keysize %d to proposal",
                               (int) key_size));
                    ike_error =
                        ssh_ikev2_sa_add(
                                ike_sa_payload, proposal_index,
                                SSH_IKEV2_TRANSFORM_TYPE_PRF,
                                mac->ike_prf_transform_id,
                                SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE
                                (key_size));
                }
            }
        }
    }

    return ike_error;
}


static SshIkev2Error
ssh_pm_sa_build_dh_groups_from_tunnel(SshPm pm,
                                      SshPmTunnel tunnel,
                                      SshIkev2PayloadSA ike_sa_payload,
                                      int proposal_index,
                                      bool ike_proposal,
                                      int num_dh_groups)
{
    SshIkev2Error ike_error = SSH_IKEV2_ERROR_OK;
    int i;

    for (i = 0; i < num_dh_groups && ike_error == SSH_IKEV2_ERROR_OK; i++)
    {
        SshPmDHGroup dhgroup;
        bool pfs = (ike_proposal == true ? false : true);

        dhgroup = ssh_pm_tunnel_dh_group(tunnel, i, pfs);

        SSH_ASSERT(dhgroup != NULL);

        /* Do not allow group 0 at initial exchange */
        if (ike_proposal && dhgroup->group_desc == 0)
          continue;

        ike_error = ssh_ikev2_sa_add(ike_sa_payload, proposal_index,
                                     SSH_IKEV2_TRANSFORM_TYPE_D_H,
                                     dhgroup->group_desc, 0);
    }

    return ike_error;
}



static SshIkev2Error
ssh_pm_ike_sa_build_proposal_from_tunnel(SshPm pm,
                                         SshPmTunnel tunnel,
                                         SshIkev2PayloadSA ike_sa_payload,
                                         int proposal_index,
                                         bool combined_mode)
{
    SshIkev2Error ike_error = SSH_IKEV2_ERROR_OK;
    uint32_t num_ciphers;
    uint32_t num_hashes;
    uint32_t num_dh_groups;

    /* Count how many transforms we need. */
    (void)
        ssh_pm_ike_num_algorithms(
                pm, tunnel->u.ike.algorithms,
                tunnel->u.ike.ike_groups,
                &num_ciphers, &num_hashes, &num_dh_groups);

    SSH_ASSERT(num_ciphers * num_hashes * num_dh_groups > 0);

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        ike_error =
          ssh_pm_sa_build_ciphers_from_tunnel(pm,
                                              tunnel,
                                              ike_sa_payload,
                                              proposal_index,
                                              combined_mode,
                                              /* ike_proposal: */ true,
                                              tunnel->u.ike.algorithms,
                                              /* requested_key_size: */ 0,
                                              num_ciphers);
    }

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        if (combined_mode != true)
        {
            ike_error =
              ssh_pm_sa_build_macs_from_tunnel(pm,
                                               tunnel,
                                               ike_sa_payload,
                                               proposal_index,
                                               /* ike_proposal: */ true,
                                               tunnel->u.ike.algorithms,
                                               /* requested_key_size: */ 0,
                                               num_hashes);
        }
    }

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        ike_error =
            ssh_pm_ike_sa_build_prfs_from_tunnel(ike_sa_payload,
                                                 proposal_index,
                                                 pm,
                                                 tunnel,
                                                 num_hashes);
    }

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        ike_error =
            ssh_pm_sa_build_dh_groups_from_tunnel(pm,
                                                  tunnel,
                                                  ike_sa_payload,
                                                  proposal_index,
                                                  /* ike_proposal: */ true,
                                                  num_dh_groups);
    }

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        ike_sa_payload->protocol_id[proposal_index] =
            SSH_IKEV2_PROTOCOL_ID_IKE;
    }

    return ike_error;
}


SshIkev2Error
ssh_pm_build_ike_sa_from_tunnel(SshPm pm, SshPmTunnel tunnel,
                                SshIkev2PayloadSA *sa_payload_return)
{
    SshIkev2PayloadSA ike_sa_payload = NULL;
    SshIkev2Error ike_error = SSH_IKEV2_ERROR_OK;
    bool combined_first = SSH_PM_COMBINED_MODE_FIRST;
    *sa_payload_return = NULL;

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        ike_sa_payload = ssh_ikev2_sa_allocate(pm->sad_handle);
        if (ike_sa_payload == NULL)
        {
            ike_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            return ike_error;
        }
    }

    {
        bool combined_mode = combined_first;
        int proposal_index = 0;
        int i;

        for (i = 0; i < 2 && ike_error == SSH_IKEV2_ERROR_OK; i++)
        {
            uint32_t cipher_mask;

            if (combined_mode)
            {
                cipher_mask = SSH_PM_COMBINED_MASK;
            }
            else
            {
                cipher_mask = (SSH_PM_CRYPT_MASK & ~SSH_PM_COMBINED_MASK);
            }

            if ((tunnel->u.ike.algorithms & cipher_mask) != 0)
            {
                ike_error =
                    ssh_pm_ike_sa_build_proposal_from_tunnel(pm,
                                                             tunnel,
                                                             ike_sa_payload,
                                                             proposal_index,
                                                             combined_mode);
                proposal_index++;
            }

            combined_mode = !combined_mode;
        }
    }

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        *sa_payload_return = ike_sa_payload;
    }

    if (ike_error != SSH_IKEV2_ERROR_OK)
    {
        if (ike_sa_payload != NULL)
          ssh_ikev2_sa_free(pm->sad_handle, ike_sa_payload);
    }

    return ike_error;
}

static SshIkev2Error
pm_build_ipsec_sa_proposal_from_tunnel(
        SshPm pm,
        SshPmQm qm,
        SshIkev2PayloadSA ipsec_sa_payload,
        int proposal_index,
        bool combined_mode)
{
    SshPmTunnel tunnel = qm->tunnel;
    uint32_t num_ciphers, num_macs, num_dh_groups;
    SshIkev2Error ike_error = SSH_IKEV2_ERROR_OK;

    SSH_PM_ASSERT_QM(qm);

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        /* Count how many algorithms we have. */
        (void) ssh_pm_ipsec_num_algorithms(pm,
                                           qm->transform,
                                           tunnel->u.ike.pfs_groups,
                                           &num_ciphers,
                                           &num_macs,
                                           NULL,
                                           &num_dh_groups);
    }

    if (qm->transform & SSH_PM_IPSEC_ESP)
    {
        SSH_ASSERT(num_ciphers != 0);

        if (ike_error == SSH_IKEV2_ERROR_OK)
        {
            ike_error =
                ssh_pm_sa_build_ciphers_from_tunnel(pm,
                                                    tunnel,
                                                    ipsec_sa_payload,
                                                    proposal_index,
                                                    combined_mode,
                                                    /* ike_proposal: */ false,
                                                    qm->transform,
                                                    qm->cipher_key_size,
                                                    num_ciphers);
        }

        if (combined_mode != true)
        {
            if (ike_error == SSH_IKEV2_ERROR_OK)
            {
                ike_error =
                    ssh_pm_sa_build_macs_from_tunnel(pm,
                                                     tunnel,
                                                     ipsec_sa_payload,
                                                     proposal_index,
                                                     /* ike_proposal: */ false,
                                                     qm->transform,
                                                     qm->mac_key_size,
                                                     num_macs);
            }
        }
    }
    else if (qm->transform & SSH_PM_IPSEC_AH)
    {
        uint16_t mac_key_size;

        if (qm->transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
          mac_key_size = qm->cipher_key_size;
        else
          mac_key_size = qm->mac_key_size;

        SSH_ASSERT(num_macs > 0);

        if (ike_error == SSH_IKEV2_ERROR_OK)
        {
            ike_error =
                ssh_pm_sa_build_macs_from_tunnel(pm,
                                                 tunnel,
                                                 ipsec_sa_payload,
                                                 proposal_index,
                                                 /* ike_proposal: */ false,
                                                 qm->transform,
                                                 mac_key_size,
                                                 num_macs);
        }
    }

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        /* Check for PFS group. However do not try to do Diffie-Hellman when
           creating SA's as part of the IKE exchange since the Diffie-Hellman
           was already performed at the IKE SA init stage. */
        if ((qm->ed->state != SSH_IKEV2_STATE_IKE_AUTH_1ST) &&
            (qm->ed->state != SSH_IKEV2_STATE_IKE_AUTH_LAST))
        {
            ike_error =
                ssh_pm_sa_build_dh_groups_from_tunnel(
                        pm,
                        tunnel,
                        ipsec_sa_payload,
                        proposal_index,
                        /* ike_proposal: */ false,
                        num_dh_groups);
        }
    }


    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        /* Add ESN options. As default option we add both ESN and
           NO_ESN, but if tunnel sets only SSH_PM_IPSEC_SHORTSEQ or
           SSH_PM_IPSEC_LONGSEQ, we use only the specified
           option. Setting both flags equals setting neither. */
        if ((tunnel->transform & SSH_PM_IPSEC_SHORTSEQ) ||
            !(tunnel->transform & SSH_PM_IPSEC_LONGSEQ))

        {
            ike_error = ssh_ikev2_sa_add(ipsec_sa_payload,
                                         proposal_index,
                                         SSH_IKEV2_TRANSFORM_TYPE_ESN,
                                         SSH_IKEV2_TRANSFORM_ESN_NO_ESN,
                                         0);
        }
    }

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        if ((tunnel->transform & SSH_PM_IPSEC_LONGSEQ) ||
            !(tunnel->transform & SSH_PM_IPSEC_SHORTSEQ))
        {
            ike_error = ssh_ikev2_sa_add(ipsec_sa_payload,
                                         proposal_index,
                                         SSH_IKEV2_TRANSFORM_TYPE_ESN,
                                         SSH_IKEV2_TRANSFORM_ESN_ESN,
                                         0);
        }
    }

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        SshIkev2ProtocolIdentifiers proto_id = SSH_IKEV2_PROTOCOL_ID_NONE;

        if ((qm->transform & SSH_PM_IPSEC_ESP) != 0)
        {
            proto_id = SSH_IKEV2_PROTOCOL_ID_ESP;
        }
        else
        if ((qm->transform & SSH_PM_IPSEC_AH) != 0)
        {
            proto_id = SSH_IKEV2_PROTOCOL_ID_AH;
        }

        ipsec_sa_payload->protocol_id[proposal_index] = proto_id;
    }

    return ike_error;
}

static SshIkev2Error
pm_build_ipsec_sa_from_tunnel(SshPm pm,
                              SshPmQm qm,
                              SshIkev2PayloadSA *sa_payload_return)
{
    SshIkev2PayloadSA ipsec_sa_payload;
    SshIkev2Error ike_error = SSH_IKEV2_ERROR_OK;
    bool combined_first = SSH_PM_COMBINED_MODE_FIRST;

    *sa_payload_return = NULL;

    ipsec_sa_payload = ssh_ikev2_sa_allocate(pm->sad_handle);
    if (ipsec_sa_payload == NULL)
    {
        ike_error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        return ike_error;
    }

    if ((qm->transform & SSH_PM_IPSEC_ESP) != 0)
    {
        bool combined_mode = combined_first;
        int proposal_index = 0;
        int i;

        for (i = 0; i < 2 && ike_error == SSH_IKEV2_ERROR_OK; i++)
        {
            uint32_t cipher_mask;

            if (combined_mode)
            {
                cipher_mask = SSH_PM_COMBINED_MASK;
            }
            else
            {
                cipher_mask = (SSH_PM_CRYPT_MASK & ~SSH_PM_COMBINED_MASK);
            }

            if ((qm->transform & cipher_mask) != 0)
            {
                ike_error =
                  pm_build_ipsec_sa_proposal_from_tunnel(pm,
                                                         qm,
                                                         ipsec_sa_payload,
                                                         proposal_index,
                                                         combined_mode);
                proposal_index++;
            }

            combined_mode = !combined_mode;
        }
    }
    else
    {
        SSH_ASSERT((qm->transform & SSH_PM_IPSEC_AH) != 0);

        ike_error =
            pm_build_ipsec_sa_proposal_from_tunnel(pm,
                                                   qm,
                                                   ipsec_sa_payload,
                                                   /* proposal_index: */  0,
                                                   /* combined_mode: */ false);
    }

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        *sa_payload_return = ipsec_sa_payload;
    }

    if (ike_error != SSH_IKEV2_ERROR_OK)
    {
        if (ipsec_sa_payload)
        {
            ssh_ikev2_sa_free(pm->sad_handle, ipsec_sa_payload);
        }
    }

    return ike_error;
}

static SshIkev2Error
pm_check_nat_policy(SshPm pm,
                    SshPmQm qm)
{
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
    SshPmTunnel tunnel = qm->tunnel;

    /* Check if policy allows NAT's. */
    if ((tunnel->flags & SSH_PM_T_NO_NATS_ALLOWED) &&
        (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT ||
         qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT))
    {
        ssh_pm_log_qm_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR, qm, "error");
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "  Message: negotiation aborted");
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "  Reason: Policy does not allow NAT's");

#ifdef SSHDIST_IPSEC_MOBIKE
        if (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
          return SSH_IKEV2_ERROR_UNEXPECTED_NAT_DETECTED;
        else
#endif /* SSHDIST_IPSEC_MOBIKE */
          return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

    return SSH_IKEV2_ERROR_OK;
}

/*--------------------------------------------------------------------*/
/*       IKE SPD policy calls                                         */
/*--------------------------------------------------------------------*/


/* ******************** Fill proposals for IKE SA ***************************/

SshOperationHandle
ssh_pm_ike_spd_fill_ike_sa(SshSADHandle sad_handle,
                           SshIkev2ExchangeData ed,
                           SshIkev2SpdFillSACB reply_callback,
                           void *reply_callback_context)
{
    SshPmP1 p1 = (SshPmP1)ed->ike_sa;
    SshPm pm = sad_handle->pm;
    SshIkev2PayloadSA ike_sa_payload = NULL;
    SshPmTunnel tunnel;
    SshIkev2Error ike_error;

    SSH_PM_ASSERT_P1(p1);

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
        (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, NULL,
                          reply_callback_context);
        return NULL;
    }

    if (ed->state == SSH_IKEV2_STATE_REKEY_IKE)
    {
        /* Verify that we have a completed Phase-I IKE SA */
        if (!SSH_PM_P1_READY(p1))
        {
            (*reply_callback)(SSH_IKEV2_ERROR_INVALID_ARGUMENT, NULL,
                              reply_callback_context);
            return NULL;
        }

        /* Construct the SA Payload from the IKE SA. */
        ike_error = pm_build_ike_sa_from_p1(pm, p1, &ike_sa_payload);
    }
    else
    {
        SSH_PM_ASSERT_P1N(p1);
        SSH_ASSERT(p1->done == 0);

        if (!SSH_PM_P1_USABLE(p1) || !p1->n || !p1->n->tunnel)
          goto error;

        tunnel = p1->n->tunnel;
        SSH_ASSERT(tunnel != NULL);

        SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

        ike_error =
            ssh_pm_build_ike_sa_from_tunnel(
                    pm,
                    tunnel,
                    &ike_sa_payload);
    }

#ifdef DEBUG_LIGHT
    if (ike_error == SSH_IKEV2_ERROR_OK && ike_sa_payload != NULL)
    {
        SSH_DEBUG(SSH_D_MIDOK, ("Initiator's proposing IKE SA payload %@",
                                ssh_ikev2_payload_sa_render, ike_sa_payload));
    }
#endif /* DEBUG_LIGHT */

    (*reply_callback)(ike_error, ike_sa_payload, reply_callback_context);
    return NULL;

   error:
    (*reply_callback)(
            SSH_IKEV2_ERROR_SA_UNUSABLE, NULL, reply_callback_context);
    return NULL;
}


/* *********************** Select an IKE SA proposal. ***********************/

typedef struct SshPmSpdSelectIkeSaContextRec
{
    SshOperationHandleStruct op[1];
    SshFSMThreadStruct thread[1];
    uint8_t aborted : 1;
    SshSADHandle sad_handle;
    SshIkev2ExchangeData ed;
    SshIkev2PayloadSA sa_in;
    SshIkev2SpdSelectSACB reply_callback;
    void *reply_callback_context;
} *SshPmSpdSelectIkeSaContext;

static void
pm_ike_spd_select_ike_sa_thread_destructor(SshFSM fsm, void *context)
{
    SshPmSpdSelectIkeSaContext ctx = context;

    SSH_ASSERT(ctx != NULL);

    SSH_DEBUG(SSH_D_LOWSTART, ("Select IKE SA thread destructor."));

    /* Free sa reference. */
    ssh_ikev2_sa_free(ctx->sad_handle, ctx->sa_in);

    if (!ctx->aborted)
      ssh_operation_unregister(ctx->op);

    /* Free ed reference.
       This might free the obstack this ctx was allocated from. */
    ssh_ikev2_exchange_data_free(ctx->ed);
}

static void
pm_ike_spd_select_ike_sa_abort(void *context)
{
    SshPmSpdSelectIkeSaContext ctx = context;
    SSH_DEBUG(SSH_D_LOWOK, ("Select IKE SA operation aborted"));
    ctx->aborted = 1;
}

SSH_FSM_STEP(ssh_pm_st_ike_spd_select_ike_sa_start)
{
    SshPmSpdSelectIkeSaContext ctx = thread_context;
    SshSADHandle sad_handle = ctx->sad_handle;
    SshIkev2ExchangeData ed = ctx->ed;
    SshIkev2PayloadSA sa_in = ctx->sa_in;
    SshIkev2PayloadTransform selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];
    SshIpAddr local, remote;
    SshIkev2PayloadSA sa_policy;
    SshPmP1 p1 = (SshPmP1) ctx->ed->ike_sa;
    SshPm pm = sad_handle->pm;
    SshPmTunnel tunnel = NULL;
    SshIkev2Error ike_error = SSH_IKEV2_ERROR_OK;
    int proposal_index;
    bool ikev1 = false;
    SshPmQm qm;

    SSH_DEBUG(SSH_D_LOWSTART, ("Select IKE SA thread starts."));

    SSH_DEBUG(SSH_D_MIDOK, ("Enter SA %p ED %p", ed->ike_sa, ed));
    SSH_PM_ASSERT_P1(p1);

    if (ctx->aborted)
      return SSH_FSM_FINISH;

    PM_SUSPEND_CONDITION_WAIT(pm, thread);

    if (ed->state == SSH_IKEV2_STATE_REKEY_IKE)
    {
        if (!p1->done)
        {
            (*ctx->reply_callback)(SSH_IKEV2_ERROR_INVALID_ARGUMENT, 0, NULL,
                                   ctx->reply_callback_context);
            return SSH_FSM_FINISH;
        }

        /* Construct the SA Payload from the IKE SA. */
        ike_error = pm_build_ike_sa_from_p1(pm, p1, &sa_policy);
    }
    else
    {
        SSH_PM_ASSERT_P1N(p1);
        SSH_ASSERT(!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR));
        SSH_ASSERT(p1->n->tunnel == NULL);

        qm = (SshPmQm) ed->application_context;
        if (qm)
          SSH_PM_ASSERT_QM(qm);

        /* Parse the notify payloads received from the Initiator's first
           packet. */
        ssh_pm_ike_parse_notify_payloads(ed, qm);

        /* Search for a tunnel that matches the local and remote IP
           addresses of the IKE endpoints. */
        local = ed->ike_sa->server->ip_address;
        remote = ed->ike_sa->remote_ip;

#ifdef SSHDIST_IKEV1
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
          ikev1 = true;
#endif /* SSHDIST_IKEV1 */

        SSH_DEBUG(SSH_D_HIGHOK,
                  ("Search for a tunnel matching the IKEv%d peers, "
                   "local:%@, remote:%@",
                   (ikev1 == true ? 1 : 2),
                   ssh_ipaddr_render, local,
                   ssh_ipaddr_render, remote));

        tunnel = ssh_pm_tunnel_lookup(pm, ikev1, ed->ike_sa->server,
                                      remote, sa_in,
                                      &p1->n->failure_mask,
                                      &p1->n->ike_failure_mask);
        if (tunnel == NULL)
        {
            ike_error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;

            /* If this is an IKEv2 negotiation and tunnel selection failed,
               but there was an acceptable tunnel which uses IKEv1 then
               return the error status to try IKEv1 instead. */
            if (ikev1 == false
                && (p1->n->failure_mask & SSH_PM_E_IKE_VERSION_MISMATCH))
              ike_error = SSH_IKEV2_ERROR_USE_IKEV1;

            SSH_DEBUG(SSH_D_FAIL,
                      ("No suitable tunnel found for this IKE negotiation"));

            (*ctx->reply_callback)(ike_error, 0, NULL,
                                   ctx->reply_callback_context);
            return SSH_FSM_FINISH;
        }

        SSH_DEBUG(SSH_D_LOWOK, ("Found tunnel '%s' (id %d)",
                                tunnel->tunnel_name, (int) tunnel->tunnel_id));

        /* Success. */
        SSH_ASSERT(tunnel != NULL);

        /* Store the tunnel. */
        p1->tunnel_id = tunnel->tunnel_id;
        p1->n->tunnel = tunnel;
        SSH_PM_TUNNEL_TAKE_REF(p1->n->tunnel);

        /* Re-set IKE fragmentation size because in responder case the tunnel
         * was not avaible earlier */
        if (ed->ikev2_fragmentation_supported)
          p1->ike_sa->ikev2_fragmentation_limit = tunnel->ike_fragment_size;

        /* Store tunnel flags. */
        if (tunnel->flags & SSH_PM_T_DISABLE_NATT)
          p1->ike_sa->flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T;

        /* Use the tunnel to select the transforms appropiate to our tunnel's
           policy. */
        ike_error = ssh_pm_build_ike_sa_from_tunnel(pm, tunnel, &sa_policy);
    }

    if (ike_error != SSH_IKEV2_ERROR_OK)
    {
        (*ctx->reply_callback)(
                ike_error, 0, NULL, ctx->reply_callback_context);
        return SSH_FSM_FINISH;
    }

    SSH_DEBUG(SSH_D_MIDOK, ("Responder's tunnel IKE SA payload is %@",
                            ssh_ikev2_payload_sa_render, sa_policy));
    SSH_DEBUG(SSH_D_MIDOK, ("Initiator's proposed IKE SA payload is %@",
                            ssh_ikev2_payload_sa_render, sa_in));

#ifdef SSHDIST_IKEV1
    /* Use the tunnel to set our local lifetimes to the IKE exchange data
       where it is visible to the IKEv1 fallback code. */
    if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
        SSH_ASSERT(tunnel != NULL);
        ed->ike_ed->sa_life_seconds = tunnel->u.ike.ike_sa_life_seconds;

        SSH_DEBUG(SSH_D_MIDOK, ("Set IKE SA Policy lifetimes sec=%d"
                                "to the exchange data",
                                (int) ed->ike_ed->sa_life_seconds));

        pm_ike_sa_filter_v1_compat_flags(pm, p1);
    }
#endif /* SSHDIST_IKEV1 */

    if (ssh_ikev2_sa_select(sa_in, sa_policy, &proposal_index,
                            selected_transforms,
                            NULL))
    {
        ssh_ikev2_sa_free(pm->sad_handle, sa_policy);

        /* Check the proposal index is as expected. */
        if (sa_in->protocol_id[proposal_index] != SSH_IKEV2_PROTOCOL_ID_IKE)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Unexpected proposal index, failing IKE SA "
                                   "selection."));

            (*ctx->reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
                                   0, NULL, ctx->reply_callback_context);
            return SSH_FSM_FINISH;
        }

        /* Success. */
        (*ctx->reply_callback)(SSH_IKEV2_ERROR_OK,
                               proposal_index, selected_transforms,
                               ctx->reply_callback_context);
        return SSH_FSM_FINISH;
    }
    else
    {
        ssh_ikev2_sa_free(pm->sad_handle, sa_policy);

        (*ctx->reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
                               0, NULL, ctx->reply_callback_context);

        return SSH_FSM_FINISH;
    }
    SSH_NOTREACHED;
    return SSH_FSM_FINISH;
}


SshOperationHandle
ssh_pm_ike_spd_select_ike_sa(SshSADHandle sad_handle,
                             SshIkev2ExchangeData ed,
                             SshIkev2PayloadSA sa_in,
                             SshIkev2SpdSelectSACB reply_callback,
                             void *reply_callback_context)
{
    SshPmSpdSelectIkeSaContext ctx;
    SshPmP1 p1 = (SshPmP1) ed->ike_sa;

    SSH_DEBUG(SSH_D_MIDOK, ("Enter SA %p ED %p", ed->ike_sa, ed));

    SSH_ASSERT(ed != NULL);
    SSH_PM_ASSERT_P1(p1);

    if (ssh_pm_get_status(sad_handle->pm) == SSH_PM_STATUS_SUSPENDED)
    {
        (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, 0, NULL,
                          reply_callback_context);
        return NULL;
    }

    /* RFC5996, 2.25.2:
       "If a peer receives a request to rekey an IKE SA that it is currently
       trying to close, it SHOULD reply with TEMPORARY_FAILURE."
       If this is not a rekey, then this call can also be failed with
       TEMPORARY_FAILURE as the IKEv2 library will delete the IKE SA anyway.
       Note that we are always a responder when the select_ike_sa() policy
       call is called. */
    if (!SSH_PM_P1_USABLE(p1))
    {
        (*reply_callback)(SSH_IKEV2_ERROR_TEMPORARY_FAILURE, 0, NULL,
                          reply_callback_context);
        return NULL;
    }

#ifdef SSH_PM_BLACKLIST_ENABLED
    /* Check state and execute blacklist code whenever needed. */
    switch (ed->state)
    {
      case SSH_IKEV2_STATE_REKEY_IKE:

        /* Do blacklist check */
        if (p1->enable_blacklist_check &&
            !ssh_pm_blacklist_check(
                    sad_handle->pm,
                    p1->remote_id,
                    SSH_PM_BLACKLIST_CHECK_IKEV2_R_IKE_SA_REKEY))
        {
            /* IKE ID is in blacklist. In this case No Proposal Chosen
               error is given for the callback function. */
            (*reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
                              0,
                              NULL,
                              reply_callback_context);
            return NULL;
        }
        break;

      default:
        break;
    }
#endif /* SSH_PM_BLACKLIST_ENABLED */

    /* Alloc operation context. */
    ctx = ssh_obstack_calloc(ed->obstack, sizeof(*ctx));
    if (ctx == NULL)
    {
        (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, 0, NULL,
                          reply_callback_context);
        return NULL;
    }

    ctx->sad_handle = sad_handle;
    ssh_ikev2_exchange_data_take_ref(ed);
    ctx->ed = ed;
    ssh_ikev2_sa_take_ref(sad_handle, sa_in);
    ctx->sa_in = sa_in;
    ctx->reply_callback = reply_callback;
    ctx->reply_callback_context = reply_callback_context;

    ssh_fsm_thread_init(&sad_handle->pm->fsm, ctx->thread,
                        ssh_pm_st_ike_spd_select_ike_sa_start, NULL,
                        pm_ike_spd_select_ike_sa_thread_destructor, ctx);
    ssh_fsm_set_thread_name(ctx->thread, "Select IKE SA");

    ssh_operation_register_no_alloc(ctx->op,
                                    pm_ike_spd_select_ike_sa_abort, ctx);

    return ctx->op;
}


/* ************************* Fill proposals for IPSEC SA  *******************/
#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_ISAKMP_CFG_MODE
static SshIpAddr
pm_first_ipv4_address(SshPmRemoteAccessAttrs attrs)
{
    SshIpAddr addr;
    int i;

    if (!attrs)
      return NULL;

    for (i = 0; i < attrs->num_addresses; i++)
    {
        addr = &attrs->addresses[i];
        if (SSH_IP_IS4(addr))
          return addr;
    }

    return NULL;
}

static SshIpAddr
pm_first_ipv6_address(SshPmRemoteAccessAttrs attrs)
{
    SshIpAddr addr;
    int i;

    if (!attrs)
      return NULL;

    for (i = 0; i < attrs->num_addresses; i++)
    {
        addr = &attrs->addresses[i];
        if (SSH_IP_IS6(addr))
          return addr;
    }

    return NULL;
}

/* If requested by the rule, adjust local traffic selector of an
   IKEv1-based IPsec SA according to what is received by config mode
   (when using IPsec tunnel mode) or according to the local IKE
   address (when using IPsec transport mode). */
static bool
pm_adjust_local_address(SshIkev2ExchangeData ed)
{
    SshPmQm qm = ed->application_context;
    SshPmP1 p1 = (SshPmP1)ed->ike_sa;
    SshIkev2PayloadTS ts;
    SshInetIPProtocolID proto;
    SshIpAddr addr = NULL;
    uint16_t port;
    int i;
    bool ipv6_rule;

    if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0
        || (qm->rule->flags & SSH_PM_RULE_ADJUST_LOCAL_ADDRESS) == 0)
      return true;

    ts = qm->rule->side_to.ts;
    if (ts != NULL &&
        ts->number_of_items_used > 0 &&
        SSH_IP_IS6(ts->items[0].start_address))
      ipv6_rule = true;
    else
      ipv6_rule = false;

    if ((qm->tunnel->flags & SSH_PM_T_TRANSPORT_MODE) == 0)
    {
        /* Tunnel mode, resolve inner IP header source address. */
        if (qm->rekey)
        {
            /* For IPsec SA rekeys resolve local address
               from configured virtual IP addresses. */
            if (qm->vip != NULL)
            {
                for (i = 0; i < qm->vip->num_selected_addresses; i++)
                {
                    if ((ipv6_rule == true
                         && SSH_IP_IS6(&qm->vip->selected_address[i]))
                        || (ipv6_rule == false
                            && SSH_IP_IS4(&qm->vip->selected_address[i])))
                    {
                        addr = &qm->vip->selected_address[i];
                        break;
                    }
                }
            }
        }
        else
        {
            /* For non-rekeys resolve the local address from
               the allocated remote access attributes. */
            if (ipv6_rule == true)
              addr = pm_first_ipv6_address(p1->remote_access_attrs);
            else
              addr = pm_first_ipv4_address(p1->remote_access_attrs);
        }
    }
    else
    {
        /* Transport mode */
        if ((ipv6_rule == true
             && SSH_IP_IS6(p1->ike_sa->server->ip_address))
            || (ipv6_rule == false
                && SSH_IP_IS4(p1->ike_sa->server->ip_address)))
          addr = p1->ike_sa->server->ip_address;
    }

    if (addr == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cannot set IPSec SA local address "
                   "because suitable address not available"));
        return false;
    }

    if (ed->ipsec_ed->source_ip == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Cannot set IPSec SA local address "
                   "because address not allocated"));
        return false;
    }

    memcpy(ed->ipsec_ed->source_ip, addr, sizeof *addr);

    if (SSH_IP_IS4(ed->ipsec_ed->source_ip))
      ed->ipsec_ed->source_ip->mask_len = 32;
    else
      ed->ipsec_ed->source_ip->mask_len = 128;

    ts = qm->rule->side_from.ts;
    if (ts == NULL || ts->number_of_items_used < 1)
    {
        proto = 0;
        port = 0;
    }
    else
    {
        proto = ts->items[0].proto;
        port = ts->items[0].start_port;
    }

    ed->ipsec_ed->protocol = proto;
    ed->ipsec_ed->source_port = port;

    return true;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#endif /* SSHDIST_IKEV1 */

SshOperationHandle
ssh_pm_ike_spd_fill_ipsec_sa(SshSADHandle sad_handle,
                             SshIkev2ExchangeData ed,
                             SshIkev2SpdFillSACB reply_callback,
                             void *reply_callback_context)
{
    SshPm pm = sad_handle->pm;
    SshPmQm qm = ed->application_context;
    SshPmP1 p1 = (SshPmP1)ed->ike_sa;
    SshIkev2PayloadSA ipsec_sa_payload = NULL;
    SshIkev2Error ike_error;

    SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
        (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED,
                          NULL, reply_callback_context);
        return NULL;
    }

    /* Check the case of responder IKEv1 negotiations where the IKE SA has
       been deleted (ed->application_context is cleared). */
    if (qm == NULL || !SSH_PM_P1_USABLE(p1))
    {
        (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE,
                          NULL, reply_callback_context);
        return NULL;
    }

    SSH_PM_ASSERT_QM(qm);

    if ((qm->transform & SSH_PM_IPSEC_AH) &&
        (qm->transform & SSH_PM_IPSEC_ESP))
    {
        SSH_DEBUG(SSH_D_FAIL, ("AH & ESP bundles are not supported"));
        (*reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
                          NULL, reply_callback_context);
        return NULL;
    }

#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_ISAKMP_CFG_MODE
    if (!pm_adjust_local_address(ed))
    {
        (*reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
                          NULL, reply_callback_context);
        return NULL;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#endif /* SSHDIST_IKEV1 */

    ike_error = pm_check_nat_policy(pm, qm);

    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        if (qm->rekey)
        {
            ike_error =
                pm_get_ipsec_transform_proposal(
                        pm,
                        qm->tunnel,
                        qm->old_inbound_spi,
                        &ipsec_sa_payload);
        }
        else
        {
            ike_error =
                pm_build_ipsec_sa_from_tunnel(
                        pm,
                        qm,
                        &ipsec_sa_payload);
        }
    }

#ifdef DEBUG_LIGHT
    if (ike_error == SSH_IKEV2_ERROR_OK && ipsec_sa_payload != NULL)
    {
        SSH_DEBUG(SSH_D_MIDOK,
                  ("Initiator's proposing IPSec SA payload %@",
                   ssh_ikev2_payload_sa_render, ipsec_sa_payload));
    }
#endif /* DEBUG_LIGHT */

    (*reply_callback)(ike_error, ipsec_sa_payload, reply_callback_context);
    return NULL;
}


/* ************************* Select an IPSEC SA proposal. ********************/

SshIkev2Error
pm_ike_spd_select_ipsec_sa(
        SshPm pm,
        SshIkev2PayloadSA policy_sa,
        SshIkev2ExchangeData ed,
        SshIkev2PayloadSA sa_in,
        SshIkev2PayloadTransform
        selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
        int *proposal_index)
{
    SshPmQm qm = ed->application_context;

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
      return SSH_IKEV2_ERROR_SUSPENDED;

    /* Check the case of responder IKEv1 negotiations where the IKE SA has
       been deleted (ed->application_context is cleared). */
    if (qm == NULL || !SSH_PM_P1_USABLE((SshPmP1)ed->ike_sa))
      return SSH_IKEV2_ERROR_SA_UNUSABLE;

    SSH_PM_ASSERT_QM(qm);
    SSH_ASSERT(qm->tunnel != NULL);

    /* Check if already in error state ... might be in case of simultaneus
       IPsec SA rekey. See sad_ike_spis.c for details. */
    if (qm->error != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("This SA lost on simultaneus IPsec rekey arbitration."));
        return qm->error;
    }

#ifdef SSHDIST_IKEV1
    /* Use the tunnel to set our local lifetimes to the IPSec exchange data
       where it is visible to the IKEv1 fallback code. */
    if (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
        ed->ipsec_ed->sa_life_seconds =
            qm->tunnel->u.ike.ipsec_sa_life_seconds;

        ed->ipsec_ed->sa_life_kbytes =
            qm->tunnel->u.ike.ipsec_sa_life_kb;

        SSH_DEBUG(SSH_D_MIDOK, ("Set IPSec SA Policy lifetimes sec=%d, kb=%d "
                                "to the exchange data",
                                (int) ed->ipsec_ed->sa_life_seconds,
                                (int) ed->ipsec_ed->sa_life_kbytes));
    }
#endif /* SSHDIST_IKEV1 */

    (void) pm_check_nat_policy(pm, qm);

    SSH_DEBUG(SSH_D_MIDOK, ("Responder's tunnel IPSec SA payload is %@",
                            ssh_ikev2_payload_sa_render, policy_sa));

    SSH_DEBUG(SSH_D_MIDOK, ("Initiator's proposed IPSec SA payload is %@",
                            ssh_ikev2_payload_sa_render, sa_in));

    if (ssh_ikev2_sa_select(sa_in, policy_sa, proposal_index,
                            selected_transforms,
                            &qm->ike_failure_mask))
    {
        /* Check the proposal index is as expected. */
        if ((sa_in->protocol_id[*proposal_index] !=
             SSH_IKEV2_PROTOCOL_ID_ESP &&
             sa_in->protocol_id[*proposal_index] !=
             SSH_IKEV2_PROTOCOL_ID_AH)
            || (!qm->tunnel_accepted && !qm->transport_recv))
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Unexpected proposal index, failing SA selection"));
            return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
        }

        /* Check for accidental null-none */
        if ((selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR] == NULL ||
             selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_ENCR]->id ==
             SSH_IKEV2_TRANSFORM_ENCR_NULL) &&
            selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_INTEG] == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Null encryption and null integrity, failing SA "
                       "selection"));
            return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
        }

        /* Success */
        return SSH_IKEV2_ERROR_OK;
    }
    else
    {
        return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }
}

SshOperationHandle
ssh_pm_ike_spd_select_ipsec_sa(SshSADHandle sad_handle,
                               SshIkev2ExchangeData ed,
                               SshIkev2PayloadSA sa_in,
                               SshIkev2SpdSelectSACB reply_callback,
                               void *reply_callback_context)
{
    SshIkev2Error ike_error;
    int proposal_index;
    SshIkev2PayloadTransform selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];
    SshPmQm qm = ed->application_context;
    SshIkev2PayloadSA policy_sa = NULL;

    SSH_DEBUG(SSH_D_LOWOK, ("Enter SA %p ED %p", ed->ike_sa, ed));

    if (ssh_pm_get_status(sad_handle->pm) == SSH_PM_STATUS_SUSPENDED)
    {
        (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED,
                          0, NULL, reply_callback_context);
        return NULL;
    }

    /* Check the case of responder IKEv1 negotiations where the IKE SA has
       been deleted (ed->application_context is cleared). */
    if (qm == NULL || !SSH_PM_P1_USABLE((SshPmP1)ed->ike_sa))
    {
        (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE,
                          0, NULL, reply_callback_context);
        return NULL;
    }

    SSH_PM_ASSERT_QM(qm);
    SSH_ASSERT(qm->tunnel != NULL);

    /* Check if already in error state ... might be in case of simultaneus
       IPsec SA rekey. See sad_ike_spis.c for details. */
    if (qm->error)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("This SA lost on simultaneus IPsec rekey arbitration."));
        (*reply_callback)(qm->error, 0, NULL, reply_callback_context);
        return NULL;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE
    /* Check if policy requires cfgmode for IKEv2 SAs. The check is here and
       not in ssh_pm_ike_conf_request() because this gets called for both
       initial and create child exchanges. Cfgmode cannot be required for
       IKEv1 SAs because we do not know if an IKEv1 SA is created without
       cfgmode to replace an expired IKEv1 SA that was originally negotiated
       with cfgmode. */
    if ((qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0
#ifdef SSHDIST_IKEV1
        && (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0
#endif /* SSHDIST_IKEV1 */
        && (qm->tunnel->flags & SSH_PM_TR_REQUIRE_CFGMODE)
        && qm->p1->remote_access_attrs == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Policy requires cfgmode for IKE SA, "
                   "failing child SA negotiation"));
        (*reply_callback)((int) SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED, 0, NULL,
                          reply_callback_context);
        return NULL;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

    /* For rekeyes fetch the transform object from the IPsec Control and do
       IPsec SA selection based on the old SA algorithms. We do not allow the
       algorithms to change during IPsec SA rekey. */
    if (qm->rekey)
    {
        ike_error =
            pm_get_ipsec_transform_proposal(
                    qm->tunnel->pm,
                    qm->tunnel,
                    qm->old_inbound_spi,
                    &policy_sa);
    }
    else
    {
        ike_error =
            pm_build_ipsec_sa_from_tunnel(
                    qm->tunnel->pm,
                    qm,
                    &policy_sa);
    }


    if (ike_error == SSH_IKEV2_ERROR_OK)
    {
        ike_error =
            pm_ike_spd_select_ipsec_sa(
                    sad_handle->pm,
                    policy_sa,
                    ed,
                    sa_in,
                    selected_transforms,
                    &proposal_index);
    }

    if (policy_sa != NULL)
    {
        ssh_ikev2_sa_free(sad_handle, policy_sa);
    }

    if (ike_error == SSH_IKEV2_ERROR_OK)
        (*reply_callback)(SSH_IKEV2_ERROR_OK, proposal_index,
                          selected_transforms, reply_callback_context);
    else
        (*reply_callback)(ike_error, 0, NULL, reply_callback_context);

    return NULL;
}


/* *********************** Narrow traffic selectors. *************************/

SshOperationHandle
ssh_pm_ike_narrow_traffic_selectors(SshSADHandle sad_handle,
                                    SshIkev2ExchangeData ed,
                                    SshIkev2PayloadTS ts_in_local,
                                    SshIkev2PayloadTS ts_in_remote,
                                    SshIkev2SpdNarrowCB reply_callback,
                                    void *reply_callback_context)
{
    SshIkev2PayloadTS policy_ts_local = NULL, policy_ts_remote = NULL;
    SshIkev2PayloadTS ts_local, ts_remote;
    SshPm pm = sad_handle->pm;
    SshPmQm qm = ed->application_context;
    SshIkev2Error status = SSH_IKEV2_ERROR_OK;
    SshPmP1 p1 = (SshPmP1) ed->ike_sa;
    bool free_policy_selectors = false;

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
        (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED,
                          NULL, NULL, reply_callback_context);
        return NULL;
    }

    /* Check the case of responder IKEv1 negotiations where the IKE SA has
       been deleted (ed->application_context is cleared). */
    if (qm == NULL || !SSH_PM_P1_USABLE(p1))
    {
        (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE,
                          NULL, NULL, reply_callback_context);
        return NULL;
    }

    SSH_PM_ASSERT_QM(qm);

    SSH_DEBUG(SSH_D_LOWOK, ("Enter SA %p, ED %p: TS proposal = %@ <-> %@",
                            ed->ike_sa, ed,
                            ssh_ikev2_ts_render, ts_in_local,
                            ssh_ikev2_ts_render, ts_in_remote));

    if (qm->rekey == true)
    {
        const struct IPSelectorGroup *selector_group;
        bool found;

        found =
            ipsec_sa_get_traffic_selectors(
                    pm->ipsec_control,
                    qm->old_inbound_spi,
                    &selector_group);
        if (found == true)
        {
            if (ip_selector_convert_to_ikev2ts(
                        sad_handle,
                        &policy_ts_local,
                        &policy_ts_remote,
                        selector_group)
                != true)
            {
                found = false;
            }
        }

        if (found == false)
        {
            SSH_DEBUG(SSH_D_ERROR,
                      ("Cannot get traffic selectors from the policy rule"));
            (*reply_callback)(SSH_IKEV2_ERROR_CHILD_SA_NOT_FOUND, NULL, NULL,
                              reply_callback_context);
            return NULL;
        }

        free_policy_selectors = true;
    }
    else /* Get the policy rule's traffic selectors. */
    if (!ssh_pm_rule_get_traffic_selectors(
                pm, qm->rule, qm->forward,
                &policy_ts_local, &policy_ts_remote))
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("Cannot get traffic selectors from the policy rule"));
        (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, NULL, NULL,
                          reply_callback_context);
        return NULL;
    }

    SSH_DEBUG(SSH_D_LOWOK, ("TS policy = %@ <-> %@",
                            ssh_ikev2_ts_render, policy_ts_local,
                            ssh_ikev2_ts_render, policy_ts_remote));

    /* Narrow the traffic selectors. */
    ts_local = NULL;
    ts_remote = NULL;
    if (!ssh_ikev2_ts_narrow(sad_handle, false, &ts_local,
                             ts_in_local, policy_ts_local) ||
        !ssh_ikev2_ts_narrow(sad_handle, false, &ts_remote,
                             ts_in_remote, policy_ts_remote))
    {
        SSH_DEBUG(
                SSH_D_ERROR,
                ("Could not narrow traffic selectors SA %p ED %p",
                 ed->ike_sa, ed));
        status = SSH_IKEV2_ERROR_TS_UNACCEPTABLE;

        ssh_pm_log_qm_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                            qm, "failed");
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "  Message: Could not narrow traffic selectors");
    }

    if (free_policy_selectors == true)
    {
        ssh_ikev2_ts_free(sad_handle, policy_ts_local);
        ssh_ikev2_ts_free(sad_handle, policy_ts_remote);
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        /* Enforce maximum number of traffic selector items in the narrowed
           traffic selectors. This may drop traffic selector items from the
           end of the traffic selector item list. */
        ssh_pm_ts_max_enforce(sad_handle, &ts_local);
        ssh_pm_ts_max_enforce(sad_handle, &ts_remote);
        SSH_DEBUG(SSH_D_HIGHOK, ("TS narrowed = %@ <-> %@",
                                 ssh_ikev2_ts_render, ts_local,
                                 ssh_ikev2_ts_render, ts_remote));

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE
        /* For remote access servers, we additionally need to narrow the remote
           traffic selector with the IP address(es) we have assigned to the
           client. Also the local traffic selectors need to be narrowed with
           any subnet we have provided the client access to. */
        if (qm->p1->remote_access_attrs != NULL
            && qm->p1->remote_access_attrs->num_addresses > 0
            && !SSH_PM_RULE_IS_VIRTUAL_IP(qm->rule))
        {
            SshIkev2PayloadTS ts_ras_local = NULL;
            SshIkev2PayloadTS ts_ras_remote = NULL;

            status =
                ssh_pm_narrow_remote_access_attrs(
                        pm,
                        false,
                        qm->p1->remote_access_attrs,
                        ts_local,
                        ts_remote,
                        &ts_ras_local,
                        &ts_ras_remote);

            if (status != SSH_IKEV2_ERROR_OK)
            {
                SSH_ASSERT(ts_ras_local == NULL);
                SSH_ASSERT(ts_ras_remote == NULL);
                if (status == SSH_IKEV2_ERROR_TS_UNACCEPTABLE)
                {
                    ssh_pm_log_qm_event(
                            SSH_LOGFACILITY_AUTH,
                            SSH_LOG_WARNING,
                            qm,
                            "failed");

                    ssh_log_event(
                            SSH_LOGFACILITY_AUTH,
                            SSH_LOG_ERROR,
                            "  Message: Could not narrow traffic selectors");
                }
            }
            else
            {
                /* Replace result traffic selectors with RAS narrowed. */
                SSH_ASSERT(ts_ras_local != NULL);
                SSH_ASSERT(ts_ras_remote != NULL);

                ssh_ikev2_ts_free(sad_handle, ts_local);
                ts_local = ts_ras_local;
                ssh_ikev2_ts_free(sad_handle, ts_remote);
                ts_remote = ts_ras_remote;
            }
        }
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
    }

    if (status == SSH_IKEV2_ERROR_OK)
    {
        /* Pass narrowed traffic selectors back to IKEv2 library. */
        (*reply_callback)(status, ts_local, ts_remote, reply_callback_context);
    }
    else
    {
        (*reply_callback)(status, NULL, NULL, reply_callback_context);
    }

    if (ts_local != NULL)
    {
        ssh_ikev2_ts_free(sad_handle, ts_local);
    }

    if (ts_remote != NULL)
    {
        ssh_ikev2_ts_free(sad_handle, ts_remote);
    }

    return NULL;
}


/* **************************** Notifications ********************************/

SshOperationHandle
ssh_pm_ike_spd_notify_request(SshSADHandle sad_handle,
                              SshIkev2ExchangeData ed,
                              SshIkev2SpdNotifyCB reply_callback,
                              void *reply_callback_context)
{
    SshPmQm qm = NULL;
    SshPmInfo info = NULL;
    SshPmP1 p1 = (SshPmP1) ed->ike_sa;
    SshPm pm = sad_handle->pm;

#ifdef SSHDIST_IKE_REDIRECT
    unsigned char *redirect_payload;
    size_t redirect_size;
    SshIpAddr redirected_from_addr;
#endif /* SSHDIST_IKE_REDIRECT */


    SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));





    if (ed->application_context)
    {
        info = (SshPmInfo) ed->application_context;
        switch (info->type)
        {
          case SSH_PM_ED_DATA_QM:
            qm = (SshPmQm) ed->application_context;
            info = NULL;
            SSH_PM_ASSERT_QM(qm);
            break;
          case SSH_PM_ED_DATA_INFO_QM:
            qm = info->u.qm;
            SSH_PM_ASSERT_QM(qm);
            break;
          case SSH_PM_ED_DATA_INFO_P1:
            break;
#ifdef SSHDIST_IPSEC_MOBIKE
          case SSH_PM_ED_DATA_INFO_MOBIKE:
            break;
#endif /* SSHDIST_IPSEC_MOBIKE */
          case SSH_PM_ED_DATA_INFO_OLD_SPI:
          case SSH_PM_ED_DATA_INFO_DPD:
            break;

          default:
            SSH_NOTREACHED;
        }
    }

    ssh_pm_ike_parse_notify_payloads(ed, qm);

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
    /* Announce support for certificate lookups at the initiators first
       auth packet or responders init-sa packet. For responder we have
       not yet allocated QM. */
    if ((qm == NULL && ed->state == SSH_IKEV2_STATE_IKE_INIT_SA)
        || (qm != NULL
            && qm->initiator
            && ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST))
    {
        /* We do support receiving these */
        (*reply_callback)(SSH_IKEV2_ERROR_OK,
                          SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                          SSH_IKEV2_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED,
                          NULL, 0,
                          reply_callback_context);
    }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IKE_REDIRECT

    if ( qm != NULL &&
        (pm->ike_redirect_enabled & SSH_PM_IKE_REDIRECT_MASK) != 0 &&
        (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) != 0 &&
        ed->state == SSH_IKEV2_STATE_IKE_INIT_SA)
    {
        if(qm->ike_redirected == 0) /* sending 1st packet */
        {
            SSH_DEBUG(SSH_D_MY, ("Adding REDIRECT_SUPPORTED notify"));
            (*reply_callback)(SSH_IKEV2_ERROR_OK,
                          SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                          SSH_IKEV2_NOTIFY_REDIRECT_SUPPORTED,
                          NULL, 0,
                          reply_callback_context);
        }
          /* we have been redirected */
        else if (qm->ike_redirected > 0)
        {
            /* set redirected flag for rekey */
            ed->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_REDIRECTED;
            redirected_from_addr = qm->tunnel->ike_redirect_addr;

            /* Build the REDIRECTED_FROM payload */
            redirect_size = 2 + SSH_IP_ADDR_LEN(redirected_from_addr);
            redirect_payload = ssh_malloc(redirect_size);
            if (redirect_payload == NULL)
            {
                SSH_DEBUG(SSH_D_ERROR, ("Error allocating memory"));
                return NULL;
            }
            /* GW Ident Type */
            redirect_payload[0] = SSH_IP_IS4(redirected_from_addr) ?
                                  SSH_IKEV2_REDIRECT_GW_IDENT_IPV4 :
                                  SSH_IKEV2_REDIRECT_GW_IDENT_IPV6;
            /* GW Ident Len and address*/
            SSH_IP_ENCODE(redirected_from_addr, redirect_payload + 2,
                          redirect_payload[1]);

            SSH_DEBUG(SSH_D_MY, ("Adding REDIRECTED_FROM notify"));
            (*reply_callback)(SSH_IKEV2_ERROR_OK,
                          SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                          SSH_IKEV2_NOTIFY_REDIRECTED_FROM,
                          redirect_payload, redirect_size,
                          reply_callback_context);

            ssh_free(redirect_payload);
        }
    }

#endif /* SSHDIST_IKE_REDIRECT */

#ifdef SSHDIST_IPSEC_MOBIKE
    /* If initiator supports mobike and local policy supports mobike,
       then reply that we (as responder) support it too. */
    if (p1 && p1->n
        && (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0
        && ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST
        && p1->n->peer_supports_mobike
#ifdef SSH_IKEV2_MULTIPLE_AUTH
        && (!ed->ike_ed->resp_require_another_auth ||
            (ed->ike_ed->authentication_round == 2))
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        && (p1->n->tunnel->flags & SSH_PM_T_MOBIKE))
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Peer supports MobIKE, we support MobIKE"));
        (*reply_callback)(SSH_IKEV2_ERROR_OK,
                          SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                          SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED,
                          NULL, 0,
                          reply_callback_context);
    }

    if (info && info->type == SSH_PM_ED_DATA_INFO_DPD
        && (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
        && (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR))
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("DPD for MobIKE initiator SA, adding "
                                     "address update notification"));
        (*reply_callback)(SSH_IKEV2_ERROR_OK,
                          SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                          SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES,
                          NULL, 0,
                          reply_callback_context);

    }
#endif /* SSHDIST_IPSEC_MOBIKE */

    if (p1 && p1->n
        && p1->n->tunnel
        && (ed->state == SSH_IKEV2_STATE_IKE_INIT_SA)
        && (p1->n->tunnel->ike_fragment_size !=
            SSH_PM_IKE_FRAGMENTATION_DISABLED))
    {
        /*  Add fragmentation notify if we are initiator or if we are
         *  responder and peer supports it */
        if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR ||
            ed->ikev2_fragmentation_supported)
        {
            SSH_DEBUG(
                    SSH_D_NICETOKNOW,
                    ("Add fragmentation supported notify"));
            (*reply_callback)(SSH_IKEV2_ERROR_OK,
                          SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                          SSH_IKEV2_NOTIFY_FRAGMENTATION_SUPPORTED,
                          NULL, 0,
                          reply_callback_context);
        }
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
    /* If the tunnel is set to require multiple authentications AND
       we are responder in init-state */
    if (p1 && p1->n
        && p1->n->tunnel && p1->n->tunnel->second_auth_domain_name
        && !(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        && (ed->state == SSH_IKEV2_STATE_IKE_INIT_SA))
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Add multiple authentication notify"));
        (*reply_callback)(SSH_IKEV2_ERROR_OK,
                          SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                          SSH_IKEV2_NOTIFY_MULTIPLE_AUTH_SUPPORTED,
                          NULL, 0,
                          reply_callback_context);
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

#ifdef SSHDIST_IKE_EAP_AUTH
    if (p1 && p1->n && p1->n->tunnel &&
        (p1->n->tunnel->flags & SSH_PM_T_EAP_ONLY_AUTH) &&
        (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
#ifdef SSHDIST_IKEV1
        !(ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
#endif /* SSHDIST_IKEV1 */
        ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Add EAP only auth notify"));
        (*reply_callback)(SSH_IKEV2_ERROR_OK,
                          SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                          SSH_IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION,
                          NULL, 0,
                          reply_callback_context);
    }
#endif /* SSHDIST_IKE_EAP_AUTH */

    if (qm)
    {
        /* Send initial contact notification if appropiate */
        if (qm->send_initial_contact
            && qm->initiator
            && (
#ifdef SSHDIST_IKEV1
                ((ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
                 && ed->state == SSH_IKEV2_STATE_IKE_INIT_SA)
                ||
#endif /* SSHDIST_IKEV1 */
                ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST))
        {
            SSH_DEBUG(SSH_D_LOWSTART, ("Sending Initial contact notify"));

            (*reply_callback)(SSH_IKEV2_ERROR_OK,
                              SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                              SSH_IKEV2_NOTIFY_INITIAL_CONTACT,
                              NULL, 0,
                              reply_callback_context);
        }

        /* Set IKE SA receive window size if not already set (done on last
           auth packet, information and create-child exchanges only). */
        if (qm->tunnel && qm->p1
            && (qm->tunnel->ike_window_size
                != qm->p1->ike_sa->receive_window->window_size)
            && (ed->state == SSH_IKEV2_STATE_CREATE_CHILD
                || ed->state == SSH_IKEV2_STATE_INFORMATIONAL
                || (qm->initiator
                    && ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST)
                || (!qm->initiator
                    && ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST)))
        {
            unsigned char buffer[4];
            SSH_DEBUG(SSH_D_LOWSTART,
                      ("Sending IKE window size notification for size %d",
                       (int) qm->tunnel->ike_window_size));

            SSH_PUT_32BIT(buffer, qm->tunnel->ike_window_size);
            (*reply_callback)(SSH_IKEV2_ERROR_OK,
                              SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                              SSH_IKEV2_NOTIFY_SET_WINDOW_SIZE,
                              buffer, sizeof(buffer),
                              reply_callback_context);
        }

        /* Notification messages specific to IPSec. Either on
           create-child exchange or last message of init-sa exchange. */
        if (ed->state == SSH_IKEV2_STATE_CREATE_CHILD
            || (qm->initiator
                && ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST)
            || (!qm->initiator
                && ed->state == SSH_IKEV2_STATE_IKE_AUTH_LAST))
        {
            /* Send transport notification if the tunnel specifies and:
               - This is rekey for transport-mode qm OR
               - We are initiator during auth exchange OR
               - We are responder and have received this payload */
            if ((qm->tunnel && (qm->tunnel->flags & SSH_PM_T_TRANSPORT_MODE))
                &&
                (((ed->state == SSH_IKEV2_STATE_CREATE_CHILD)
                  && ((qm->transform & SSH_PM_IPSEC_TUNNEL) == 0))
                 ||
                 ((ed->state != SSH_IKEV2_STATE_CREATE_CHILD)
                  && (qm->initiator || qm->transport_recv))))
            {
                SSH_DEBUG(
                        SSH_D_LOWSTART,
                        ("Sending notify message requesting transport mode"));
                qm->transport_sent = 1;

                (*reply_callback)(SSH_IKEV2_ERROR_OK,
                                  SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                                  SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE,
                                  NULL, 0,
                                  reply_callback_context);
            }

            if (qm->transform & SSH_PM_IPSEC_ESP)
            {
                /* We do not support TFC padding, indicate this. */
                (*reply_callback)(
                        SSH_IKEV2_ERROR_OK,
                        SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                        SSH_IKEV2_NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED,
                        NULL, 0,
                        reply_callback_context);
            }

            /* Non-first fragments are processed by the same SA as first
               fragments, indicate this. */
            (*reply_callback)(SSH_IKEV2_ERROR_OK,
                              SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                              SSH_IKEV2_NOTIFY_NON_FIRST_FRAGMENTS_ALSO,
                              NULL, 0,
                              reply_callback_context);
        }
    }

    (*reply_callback)(SSH_IKEV2_ERROR_OK,
                      SSH_IKEV2_PROTOCOL_ID_NONE, NULL, 0,
                      SSH_IKEV2_NOTIFY_RESERVED, NULL, 0,
                      reply_callback_context);

    return NULL;
}

void
ssh_pm_ike_spd_notify_received(SshSADHandle sad_handle,
                               SshIkev2NotifyState notify_state,
                               SshIkev2ExchangeData ed,
                               SshIkev2ProtocolIdentifiers protocol_id,
                               unsigned char *spi,
                               size_t spi_size,
                               SshIkev2NotifyMessageType notify_message_type,
                               unsigned char *notification_data,
                               size_t notification_data_size)
{
    SshPm pm = sad_handle->pm;
    uint32_t outbound_spi;
    SshInetIPProtocolID ipproto = SSH_IPPROTO_ANY;
    SshPmP1 p1 = (SshPmP1)ed->ike_sa;
    SshPmQm qm = NULL;
    SshPmInfo info = NULL;
    bool authenticated = false;
#ifdef SSHDIST_IKE_REDIRECT
    SshIpAddrStruct redirect_addr;
#endif /* SSHDIST_IKE_REDIRECT */





    if (notify_state == SSH_IKEV2_NOTIFY_STATE_AUTHENTICATED_INITIAL ||
        notify_state == SSH_IKEV2_NOTIFY_STATE_AUTHENTICATED_FINAL)
      authenticated = true;

    SSH_DEBUG(SSH_D_LOWSTART,
              ("Enter SA %p, ED %p, state %d, received notification "
               "message %s authenticated=%d", ed->ike_sa,
               ed, ed->state,
               ssh_ikev2_notify_to_string(notify_message_type),
               authenticated));

    if (p1 == NULL || !SSH_PM_P1_USABLE(p1))
      return;

    if (ed->application_context)
    {
        info = (SshPmInfo) ed->application_context;
        switch (info->type)
        {
          case SSH_PM_ED_DATA_QM:
            qm = (SshPmQm) ed->application_context;
            info = NULL;
            break;
          case SSH_PM_ED_DATA_INFO_QM:
            qm = info->u.qm;
            break;
          case SSH_PM_ED_DATA_INFO_P1:
            break;
#ifdef SSHDIST_IPSEC_MOBIKE
          case SSH_PM_ED_DATA_INFO_MOBIKE:
            break;
#endif /* SSHDIST_IPSEC_MOBIKE */
          case SSH_PM_ED_DATA_INFO_OLD_SPI:
          case SSH_PM_ED_DATA_INFO_DPD:
            break;
          default:
            SSH_NOTREACHED;
        }
    }

    if (qm != NULL)
      SSH_PM_ASSERT_QM(qm);

    /* First handle unauthenticated notifies. The only unauthenticated notifies
       we process are NO_PROPOSAL_CHOSEN and AUTHENTICATION_FAILED for which
       we just log the notify without otherwise acting on it. */
    if (!authenticated)
    {
        switch (notify_message_type)
        {
          case SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN:
          case SSH_IKEV2_NOTIFY_AUTHENTICATION_FAILED:
            ssh_log_event(
                    SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "Plain-text notification `%s' (%d) "
                    "from %@:%d for protocol %s."
                    " Initiator SPI %@ Responder SPI %@",
                    ssh_find_keyword_name(ssh_ikev2_notify_to_string_table,
                                          notify_message_type),
                    notify_message_type,
                    ssh_ipaddr_render, p1->ike_sa->remote_ip,
                    p1->ike_sa->remote_port,
                    ssh_find_keyword_name
                    (ssh_ikev2_protocol_to_string_table,
                     protocol_id),
                    ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_i,
                    ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_r);
            break;

          case SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE:
            if (p1->n != NULL)
            {
                p1->n->transport_recv = 1;
                if (qm != NULL && qm->initiator && qm->transport_sent)
                {
                    SSH_DEBUG(SSH_D_LOWOK,
                              ("Responder requested transport mode, setting "
                               "exchange to use transport mode traffic "
                               "selectors"));
                    ssh_ikev2_ipsec_set_transport_mode_ts(ed, true);
                }
            }
            break;

#ifdef SSHDIST_IKE_CERT_AUTH
          case SSH_IKEV2_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED:
            if (p1->n)
              p1->n->cert_access_supported = 1;
            break;
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IPSEC_MOBIKE
          case SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED:
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Peer supports MobIKE."));
            if (p1->n)
              p1->n->peer_supports_mobike = 1;
            break;
#endif /* SSHDIST_IPSEC_MOBIKE */
          case SSH_IKEV2_NOTIFY_FRAGMENTATION_SUPPORTED:
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Peer supports Fragmentation."));
            if (p1->n->tunnel != NULL)
                p1->ike_sa->ikev2_fragmentation_limit =
                            p1->n->tunnel->ike_fragment_size;
            else
                p1->ike_sa->ikev2_fragmentation_limit = pm->ike_fragment_size;

            ed->ikev2_fragmentation_supported = true;
            break;
#ifdef SSHDIST_IKE_EAP_AUTH
          case SSH_IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION:
            SSH_PM_ASSERT_P1(p1);
            if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
                p1->n)
              p1->n->peer_supports_eap_only_auth = 1;
            else
              SSH_DEBUG(
                      SSH_D_NETGARB,
                      ("Ignoring N(EAP_ONLY_NOTIFY) payload from responder"));
            break;
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_REDIRECT
          case SSH_IKEV2_NOTIFY_REDIRECTED_FROM:
            SSH_DEBUG(SSH_D_MY,
                ("REDIRECTED_FROM received "
                 "(fall-through REDIRECT_SUPPORTED)"));
            SSH_IP_DECODE(&redirect_addr, notification_data + 2,
                          notification_data[1]);
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                              "Client %@ redirected from gateway %@.",
                              ssh_ipaddr_render, ed->remote_ip,
                              ssh_ipaddr_render, &redirect_addr);
            /* fallthrough */
          case SSH_IKEV2_NOTIFY_REDIRECT_SUPPORTED:
            SSH_DEBUG(SSH_D_NICETOKNOW, ("REDIRECT_SUPPORTED received"));
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                              "Client %@ supports redirection.",
                              ssh_ipaddr_render, &ed->remote_ip);
            /* Are we interested ? */
            if ((pm->ike_redirect_enabled & SSH_PM_IKE_REDIRECT_MASK) != 0)
              ed->redirect_supported = true;
            break;
          case SSH_IKEV2_NOTIFY_REDIRECT:
            SSH_DEBUG(SSH_D_NICETOKNOW, ("REDIRECT received"));
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                              "Received redirect from gateway %@.",
                              ssh_ipaddr_render, ed->remote_ip);
            /* Handling of this is done in the IKEv2 lib */
            break;
#endif /* SSHDIST_IKE_REDIRECT */

          default:
            SSH_DEBUG(SSH_D_MIDOK, ("Ignoring unauthenticated notify message "
                                    "of type %d", notify_message_type));
            break;
        }

        return;
    }

    /* Now process authenticated notify messages. */
    SSH_ASSERT(authenticated == true);
    switch (notify_message_type)
    {
      case SSH_IKEV2_NOTIFY_INITIAL_CONTACT:
        /* Process the initial contact notification. */
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Received an initial contact notification from `%@:%d'",
                   ssh_ipaddr_render, ed->ike_sa->remote_ip,
                   ed->ike_sa->remote_port));

        SSH_PM_ASSERT_P1(p1);
        if (p1->done && !p1->received_1contact)
          ssh_pm_process_initial_contact_notification(pm, p1);
        else
          p1->received_1contact = 1;
        break;

      case SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE:
        if (qm)
        {
            qm->transport_recv = 1;
            if (qm->initiator && qm->transport_sent)
            {
                SSH_DEBUG(
                        SSH_D_LOWOK,
                        ("Responder requested transport mode, setting "
                         "exchange to use transport mode traffic selectors"));
                ssh_ikev2_ipsec_set_transport_mode_ts(ed, true);
            }
        }
        break;

      case SSH_IKEV2_NOTIFY_INVALID_SELECTORS:

        /* Apparently we have sent IPsec packets whose selectors do not match
           those of the SA on which it was delivered. If this message is
           received, our SA state has most likely been corrupted, and we
           should tear down this SA. */
        SSH_PM_ASSERT_P1(p1);

        if (protocol_id == SSH_IKEV2_PROTOCOL_ID_AH)
          ipproto = SSH_IPPROTO_AH;
        else if (protocol_id == SSH_IKEV2_PROTOCOL_ID_ESP)
          ipproto = SSH_IPPROTO_ESP;
        else
          return;

        /* Ignore notification messages with a corrupt SPI size. */
        if (spi_size != 4)
          return;

        outbound_spi = SSH_GET_32BIT(spi);

        /* Delete IPsec SA from the dataplane and send delete notification
           for the inbound SPI. */

        /* Lookup the SA using the outbound SPI, and send a delete
           notification for the respective inbound SPI. */
        {
          uint32_t inbound_spi;

          inbound_spi =
              ssh_pm_delete_by_spi(
                      pm,
                      outbound_spi,
                      p1->ike_sa->server->routing_instance_id,
                      ipproto,
                      p1->ike_sa->remote_ip,
                      p1->ike_sa->remote_port);

         if (inbound_spi != 0)
            {
                ssh_pm_send_ipsec_delete_notification(
                        pm,
                        ssh_pm_peer_handle_by_p1(pm, p1),
                        NULL,
                        NULL,
                        ipproto,
                        inbound_spi);
            }
        }
        break;

      case SSH_IKEV2_NOTIFY_INVALID_SPI:
        /* The peer does not know the SPI we are using for sending IPSec
           packets. Just delete the SPI. */
        SSH_PM_ASSERT_P1(p1);

        if (protocol_id == SSH_IKEV2_PROTOCOL_ID_AH)
          ipproto = SSH_IPPROTO_AH;
        else if (protocol_id == SSH_IKEV2_PROTOCOL_ID_ESP)
          ipproto = SSH_IPPROTO_ESP;
        else
          return;

        /* Ignore notification messages with a corrupt SPI size. */
        if (spi_size != 4)
          return;

        outbound_spi = SSH_GET_32BIT(spi);

        ssh_pm_invalid_spi_notify(pm, SSH_PM_IKE_SA_INDEX(p1),
                                  p1->ike_sa->server->ip_address,
                                  p1->ike_sa->remote_ip,
                                  p1->ike_sa->remote_port,
                                  ipproto, outbound_spi);
        break;

      case SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED:
#ifdef SSHDIST_IPSEC_IPCOMP
        if (qm
            && (qm->transform & SSH_PM_IPSEC_IPCOMP)
            && (qm->ipcomp_chosen == 0)
            && (notification_data_size == 3))
        {
            if (qm->initiator)
            {
                /* Read the selected IPCOMP from response. */
                qm->ipcomp_spi_out = SSH_GET_16BIT(notification_data);
                qm->ipcomp_chosen = SSH_GET_8BIT(notification_data + 2);
            }
            else
            {
                uint8_t proposed;

                /* Responder does selection here, prosessing the
                   initiator request against policy. */







                proposed = SSH_GET_8BIT(notification_data + 2);

                if (((qm->transform & SSH_PM_COMPRESS_DEFLATE)
                     && (proposed == SSH_IKEV2_IPCOMP_DEFLATE))
                    ||
                    ((qm->transform & SSH_PM_COMPRESS_LZS)
                     && (proposed == SSH_IKEV2_IPCOMP_LZS)))
                {
                    qm->ipcomp_chosen = proposed;
                    qm->ipcomp_spi_out = SSH_GET_16BIT(notification_data);
                }
            }
        }
#endif /* SSHDIST_IPSEC_IPCOMP */
        break;

      case SSH_IKEV2_NOTIFY_ADDITIONAL_TS_POSSIBLE:
        if (qm)
          qm->additional_ts_received = 1;
        break;

      case SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD:
        /* Wrong guess of D-H group when creating child SA. Need to
           restart current operation. */
        if (protocol_id != SSH_IKEV2_PROTOCOL_ID_IKE
            && ed->state == SSH_IKEV2_STATE_CREATE_CHILD
            && qm
            && qm->initiator)
        {
            SshPmQm newqm, n, p;

            /* Copy QM */
            if ((newqm = ssh_pm_qm_alloc(pm, qm->rekey)) == NULL)
              return;
            n = newqm->next;
            p = newqm->prev;
            memcpy(newqm, qm, sizeof(*qm));

            /* Reinit */
            newqm->error = SSH_IKEV2_ERROR_OK;
            newqm->ike_done = 0;
            newqm->transport_sent = 0;
            newqm->transport_recv = 0;
            newqm->ed = NULL;

            newqm->next = n;
            newqm->prev = p;

            /* Steal traffic selectors, tunnel, SPIs, and
               packet from old QM. */
            qm->packet = NULL;

            /* Explicitly move rule and tunnel references to newqm for clarity.
             */
            SSH_PM_RULE_LOCK(newqm->rule);
            SSH_PM_RULE_UNLOCK(pm, qm->rule);
            qm->rule = NULL;

            if (newqm->tunnel)
              SSH_PM_TUNNEL_TAKE_REF(newqm->tunnel);
            if (newqm->p1_tunnel)
              SSH_PM_TUNNEL_TAKE_REF(newqm->p1_tunnel);

            if (newqm->peer_handle != SSH_IPSEC_INVALID_INDEX)
              ssh_pm_peer_handle_take_ref(pm, newqm->peer_handle);

            qm->local_ts = qm->remote_ts = NULL;
            qm->local_trigger_ts = qm->remote_trigger_ts = NULL;
            qm->allocated_inbound_spi = 0;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
            /* Move VIP object reference to new QM. */
            newqm->vip = qm->vip;
            qm->vip = NULL;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

            ssh_fsm_thread_init(&pm->fsm,
                                &newqm->thread, ssh_pm_st_qm_i_n_restart_qm,
                                NULL_FNPTR, pm_qm_thread_destructor, newqm);
        }
        break;

      case SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN:
      case SSH_IKEV2_NOTIFY_AUTHENTICATION_FAILED:
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                      "Authenticated notification `%s' (%d) "
                      "from %@:%d for protocol %s."
                      " Initiator SPI %@ Responder SPI %@",
                      ssh_find_keyword_name(ssh_ikev2_notify_to_string_table,
                                            notify_message_type),
                      notify_message_type,
                      ssh_ipaddr_render, p1->ike_sa->remote_ip,
                      p1->ike_sa->remote_port,
                      ssh_find_keyword_name(ssh_ikev2_protocol_to_string_table,
                                            protocol_id),
                      ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_i,
                      ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_r);
        break;

#ifdef SSHDIST_IPSEC_MOBIKE
      case SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES:
        if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
        {
            SSH_DEBUG(
                    SSH_D_UNCOMMON,
                    ("Received address update for non-MobIKE SA %p, ignoring",
                     p1->ike_sa));
        }
        else if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR)
                 == 0)
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Received address update notify from peer for IKE SA %p",
                     p1->ike_sa));
        }
        else
        {
            SSH_DEBUG(SSH_D_UNCOMMON,
                      ("Responder sent us an address update"
                       " for IKE SA %p, ignoring", p1->ike_sa));
        }
        break;

      case SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS:
      case SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS:
      case SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES:
        if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
        {
            SSH_DEBUG(SSH_D_UNCOMMON,
                      ("Received additional address notify for "
                       "non-MobIKE SA %p, ignoring",
                       p1->ike_sa));
        }
        else
        {
            SSH_DEBUG(SSH_D_MIDOK, ("Additional addresses notify received"));
        }
        break;
#endif /* SSHDIST_IPSEC_MOBIKE */

      default:
        break;
    }
}


void
ssh_pm_ike_spd_responder_exchange_done(SshSADHandle sad_handle,
                                       SshIkev2Error error,
                                       SshIkev2ExchangeData ed)
{
    SshPm pm = sad_handle->pm;
    SshPmP1 p1 = (SshPmP1) ed->ike_sa;
    SshIkev2PayloadNotify notify;
#ifdef SSHDIST_IPSEC_MOBIKE
    bool address_update_received = false;
    bool additional_addresses_received = false;
#endif /* SSHDIST_IPSEC_MOBIKE */

    /* Currently this policy call is not called for IKEv1 SAs, as the
       only need for this call is to export the IKEv2 SAs, to trigger
       MOBIKE operations and to store the nonces for IKEv2 keyed simultaneous
       IPsec SA rekeys. If some IKEv1 specific functionality is added here
       then the IKEv2 fallback code must be modified to call this policy
       call. */

    /* Update IKE SA. */
    switch (ed->state)
    {
        /* Do not update IKE SA for initial exchanges. */
      case SSH_IKEV2_STATE_IKE_INIT_SA:
      case SSH_IKEV2_STATE_IKE_AUTH_1ST:
#ifdef SSHDIST_IKE_EAP_AUTH
      case SSH_IKEV2_STATE_IKE_AUTH_EAP:
#endif /* SSHDIST_IKE_EAP_AUTH */
      case SSH_IKEV2_STATE_IKE_AUTH_LAST:
        break;

        /* Update old rekeyed IKE SA eventhough it is marked unusable. */
      case SSH_IKEV2_STATE_REKEY_IKE:
        ssh_pm_ike_sa_event_updated(pm, p1);
        break;

        /* Check for simultaneous IPsec SA rekeys and update IKE SA after
           successfull CREATE_CHILD exchange. */
      case SSH_IKEV2_STATE_CREATE_CHILD:
        if (error == SSH_IKEV2_ERROR_OK)
          ssh_pm_qm_simultaneous_rekey_store_nonces(pm, ed);
        if (!p1->unusable)
          ssh_pm_ike_sa_event_updated(pm, p1);
        break;

        /* Update IKE SA after successfull INFORMATIONAL exchange. */
      default:
        if (!p1->unusable)
          ssh_pm_ike_sa_event_updated(pm, p1);
        break;
    }

    if (error != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Responder exchange failed"));
        return;
    }

    /* Iterate through received notifies. */
    for (notify = ed->notify; notify != NULL; notify = notify->next_notify)
    {
        switch (notify->notify_message_type)
        {
#ifdef SSHDIST_IPSEC_MOBIKE
          case SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES:
            if (ed->info_ed != NULL
                && ed->info_ed->unexpected_nat_detected == 0
                && address_update_received == false)
            {
                address_update_received = true;
                ssh_pm_mobike_address_update_received(pm, p1, ed);
            }
            break;

          case SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS:
          case SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS:
          case SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES:
            if (additional_addresses_received == false)
            {
                additional_addresses_received = true;
                ssh_pm_mobike_additional_addresses_received(pm, p1, ed);
            }
            break;
#endif /* SSHDIST_IPSEC_MOBIKE */

          default:
            break;
        }
    }
}
