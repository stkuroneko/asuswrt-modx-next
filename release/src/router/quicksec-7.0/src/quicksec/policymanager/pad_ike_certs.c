/**
   @copyright
   Copyright (c) 2005 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKE policy manager function calls related to certificates.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "x509internal.h"

#define SSH_DEBUG_MODULE "SshPmIkeCerts"

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT

/***************************** Internal utility functions ********************/

struct SshPmIkeCMParam
{
    SshSADHandle sad_handle;
    SshPmP1 p1;

    /* Authentication domain used for this search. When validating local
       cert this is default one, on remote case this can be any. */
    SshPmAuthDomain ad;

    /* Validate certificate chain from a CA to the end entity cert */
    bool create_path;
    /* Return intermediate CA certs */
    bool return_path;

    SshIkev2PayloadID ee_key;

    SshPublicKey public_key;

    SshFSMThread thread;

    SshIkev2Error error_code;
    bool search_done;

    /* Validation round counter. */
    int validation_round_count;

    /* The user certificate we are currently finding a path to. */
    int user_index;

    /* The CA we are currently finding a path to. */
    int ca_index;

    /* Iteration based on the CA information in cert request. */
    int p1_ca_index;

    bool ignore_user_cache_id;

    SshX509PkAlgorithm key_type;
};


static struct SshPmIkeCMParam *
pm_ike_certs_param_alloc(
        SshSADHandle sad_handle,
        SshPmP1 p1,
        SshPmAuthDomain ad,
        SshX509PkAlgorithm key_type,
        SshIkev2PayloadID payload_id)
{
    struct SshPmIkeCMParam *param;

   /* Allocate context for callback */
    param = ssh_calloc(1, sizeof(*param));
    if (param != NULL)
    {
        param->sad_handle = sad_handle;

        param->p1 = p1;
        /* Take a reference to the IKE SA. */
        SSH_PM_IKE_SA_TAKE_REF(p1->ike_sa);

        param->ad = ad;
        ssh_pm_auth_domain_take_ref(ad);

        param->key_type = key_type;
        param->ee_key = payload_id;
    }

    return param;
}

static void
pm_ike_certs_param_free(
        struct SshPmIkeCMParam *param)
{
    SshSADHandle sad_handle = param->sad_handle;
    SshPm pm = sad_handle->pm;
    SshPmAuthDomain ad = param->ad;
    SshPmP1 p1 = param->p1;

    SSH_PM_IKE_SA_FREE_REF(sad_handle, p1->ike_sa);
    ssh_pm_ikev2_payload_id_free(param->ee_key);
    ssh_pm_auth_domain_destroy(pm, ad);
    ssh_free(param);
}

static SshX509PkAlgorithm
pm_ike_certs_get_key_type(
        SshIkev2ExchangeData ed)
{
    SshX509PkAlgorithm key_type;

#ifdef SSHDIST_IKEV1
    if ((ed->ike_ed->auth_method ==
         SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES)
#ifdef SSHDIST_IKE_XAUTH
        || (ed->ike_ed->auth_method ==
            SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES)
        || (ed->ike_ed->auth_method ==
            SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_SIGNATURES)
#endif /* SSHDIST_IKE_XAUTH */
        )
    {
        key_type = SSH_X509_PKALG_RSA;
    }
    else
    if ((ed->ike_ed->auth_method ==
         SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES)
#ifdef SSHDIST_IKE_XAUTH
        || (ed->ike_ed->auth_method ==
            SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES)
        || (ed->ike_ed->auth_method ==
            SSH_IKE_VALUES_AUTH_METH_XAUTH_R_DSS_SIGNATURES)
#endif /* SSHDIST_IKE_XAUTH */
        )
    {
        key_type = SSH_X509_PKALG_DSA;
    }
#ifdef SSHDIST_CRYPT_ECP
    else
    if ((ed->ike_ed->auth_method ==
         SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256)
        || (ed->ike_ed->auth_method ==
            SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384)
        || (ed->ike_ed->auth_method ==
            SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521))
    {
        key_type = SSH_X509_PKALG_ECDSA;
    }
#endif /* SSHDIST_CRYPT_ECP */
    else
#endif /* SSHDIST_IKEV1 */
    {
        key_type = SSH_X509_PKALG_UNKNOWN;
    }

    return key_type;
}

static unsigned char *
pm_ike_certs_compute_key_id(
        SshPmCa ca,
        size_t *kid_len)
{
    unsigned char *kid;
    SshX509Certificate x509;

    if (ssh_cm_cert_get_x509(ca->cert, &x509) != SSH_CM_STATUS_OK ||
        x509 == NULL)
    {
        return NULL;
    }

    kid = ssh_x509_cert_compute_key_identifier_ike(x509, "sha1", kid_len);

    ssh_x509_cert_free(x509);

    return kid;
}

static int
pm_ike_certs_render(
        char *buf,
        int buf_size,
        int precision,
        void *datum)
{
    SshCMCertificate cmcert = datum;
    bool ok = false;
    int len = 0;

    if (cmcert != NULL)
    {
        SshX509Certificate x509;
        SshCMStatus status;

        status = ssh_cm_cert_get_x509(cmcert, &x509);
        if (status != SSH_CM_STATUS_OK || x509 == NULL)
        {
            ok = false;
        }
        else
        {
            SshMPIntegerStruct mp_integer;
            char *serial_number = NULL;
            char *name;

            ssh_mprz_init(&mp_integer);
            ok = ssh_x509_cert_get_serial_number(x509, &mp_integer);
            if (ok == true)
            {
                serial_number = ssh_mprz_get_str(&mp_integer, 10);
            }

            ok = ssh_x509_cert_get_subject_name(x509, &name);
            if (ok == true)
            {
                if (serial_number != NULL)
                {
                    len =
                        ssh_snprintf(
                                buf,
                                buf_size + 1,
                                "'%s' (S/N=%s)",
                                name,
                                serial_number);
                }
                else
                {
                    len =
                        ssh_snprintf(
                                buf,
                                buf_size + 1,
                                "'%s'",
                                name);
                }

                ssh_free(name);
            }

            if (serial_number != NULL)
            {
                ssh_free(serial_number);
            }

            ssh_mprz_clear(&mp_integer);
            ssh_x509_cert_free(x509);
        }
    }

    if (ok == false)
    {
        len = ssh_snprintf(buf, buf_size + 1, "'%s'", "UNKNOWN");
    }

    if (len >= buf_size)
    {
        return buf_size + 1;
    }

    return len;
}

/* Information structure of certificate request */
struct SshPmCertRequestInfo
{
    /* true, if IKEv1 used */
    bool is_ikev1;

    /* Certificate request */
    unsigned char *request;

    /* Length of certificate request */
    size_t len;
};

static int
pm_ike_certs_request_render(
        char *buf,
        int buf_size,
        int precision,
        void *datum)
{
    struct SshPmCertRequestInfo *info = datum;
    bool ok = true;
    int len = 0;

    if (info != NULL)
    {
        unsigned char *request = info->request;
        size_t request_len = info->len;

        if (info->is_ikev1 == true)
        {
            SshDNStruct dn;
            char *ldap_dn;

            ok = false;

            ssh_dn_init(&dn);
            if (ssh_dn_decode_der(request, request_len, &dn, NULL))
            {
                if (ssh_dn_encode_ldap(&dn, &ldap_dn))
                {
                    len = ssh_snprintf(buf, buf_size + 1, "%s", ldap_dn);

                    ssh_free(ldap_dn);
                    ok = true;
                }
            }
            ssh_dn_clear(&dn);
        }
        else
        {
            int i;

            for (i = 0; i < request_len && len < buf_size; i++)
            {
                if (ssh_snprintf(
                            buf + len,
                            buf_size - len,
                            "%02x",
                            request[i])
                    < 0)
                {
                    ok = false;
                    break;
                }

                len += 2;
            }
        }
    }

    if (ok == false)
    {
        len = ssh_snprintf(buf, buf_size + 1, "%s", "UNKNOWN");
    }

    if (len >= buf_size)
    {
        return buf_size + 1;
    }

    return len;
}

static SshCMCertificate
pm_ike_certs_get_ca_cert(
        struct SshPmIkeCMParam *param)
{
    SshCMCertificate cmcert = NULL;
    SshPmAuthDomain ad = param->ad;

    if (param->ca_index < ad->num_cas)
    {
        SshPmCa ca;

        ca = ad->cas[param->ca_index];
        if (ca != NULL)
        {
            cmcert = ca->cert;
        }
    }

    return cmcert;
}

static SshCMCertificate
pm_ike_certs_get_local_cert(
        struct SshPmIkeCMParam *param)
{
    SshPmP1 p1 = param->p1;
    SshCMCertificate cmcert = NULL;

    if (p1 != NULL && p1->n != NULL && p1->n->tunnel != NULL)
    {
        SshPmTunnel tunnel = p1->n->tunnel;

        if (tunnel->u.ike.local_cert_kid != NULL)
        {
            cmcert =
                ssh_pm_get_certificate_by_kid(
                        param->sad_handle->pm,
                        tunnel->u.ike.local_cert_kid,
                        tunnel->u.ike.local_cert_kid_len);
        }
    }

    return cmcert;
}

static SshCMCertificate
pm_ike_certs_get_user_cert(
        struct SshPmIkeCMParam *param)
{
    SshPmP1 p1 = param->p1;
    SshCMCertificate cmcert = NULL;

    if (p1 != NULL && p1->n != NULL)
    {
        uint32_t cache_id = p1->n->user_certificate_ids[param->user_index];
        SshCMContext cm = param->ad->cm;

        if (cm != NULL)
        {
            cmcert = ssh_pm_get_certificate_by_cache_id(cm, cache_id);
        }
    }

    return cmcert;
}

static void
pm_ike_certs_validator_error(
        SshCMSearchInfo info)
{
    if (info->error_string != NULL)
    {
        char *tmp = (char *) info->error_string;
        size_t len;

        for (len = strlen(tmp);
             len > 0;
             tmp = tmp + len + 1, len = strlen(tmp))
        {
            ssh_log_event(
                    SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_ERROR,
                    "%s",
                    tmp);
        }
    }
    else
    {
        ssh_log_event(
                SSH_LOGFACILITY_LOCAL0,
                SSH_LOG_INFORMATIONAL,
                "Failed with reason: Validator has returned an error");
    }
}

static void
pm_ike_certs_remote_validation_progress(
        struct SshPmIkeCMParam *param,
        bool success)
{
    SshLogFacility facility = SSH_LOGFACILITY_LOCAL0;
    SshIkev2PayloadID payload_id = param->ee_key;
    char *result_string;

    if (success == true)
    {
        result_string = "succeeded";
    }
    else
    {
        result_string = "failed";
    }

    if (param->ignore_user_cache_id == false)
    {
        ssh_log_event(
                facility,
                SSH_LOG_INFORMATIONAL,
                "Validation %s for remote identity '%@' and "
                "remote certificate %@ against trust anchor %@",
                result_string,
                ssh_pm_ike_id_render, payload_id,
                pm_ike_certs_render, pm_ike_certs_get_user_cert(param),
                pm_ike_certs_render, pm_ike_certs_get_ca_cert(param));
    }
    else
    {
        ssh_log_event(
                facility,
                SSH_LOG_INFORMATIONAL,
                "Validation %s for remote identity '%@' "
                "against trust anchor %@",
                result_string,
                ssh_pm_ike_id_render, payload_id,
                pm_ike_certs_render, pm_ike_certs_get_ca_cert(param));
    }
}

static void
pm_ike_certs_remote_error(
        struct SshPmIkeCMParam *param,
        const char *error_string)
{
    pm_ike_certs_remote_validation_progress(param, false);

    ssh_log_event(
            SSH_LOGFACILITY_LOCAL0,
            SSH_LOG_INFORMATIONAL,
            "Reason: %s",
            error_string);
}

static void
pm_ike_certs_remote_validator_error(
        struct SshPmIkeCMParam *param,
        SshCMSearchInfo info)
{
    pm_ike_certs_remote_validation_progress(param, false);

    pm_ike_certs_validator_error(info);
}

static void
pm_ike_certs_remote_validation_start(
        struct SshPmIkeCMParam *param)
{
    param->validation_round_count = 0;

    ssh_log_event(
            SSH_LOGFACILITY_LOCAL0,
            SSH_LOG_INFORMATIONAL,
            "Remote certificate validation started");
}

static bool
pm_ike_certs_remote_validation_continue(
        struct SshPmIkeCMParam *param)
{
    SshPmP1 p1 = param->p1;
    SshPmP1Negotiation p1_neg = p1->n;
    bool proceed = true;

    /* Check if this is the first round. */
    if (param->validation_round_count == 0)
    {
        if (p1_neg->num_user_certificate_ids == 0)
        {
            param->ignore_user_cache_id = true;
        }
        else
        {
            param->ignore_user_cache_id = false;
        }
    }
    else
    {
        SshPmAuthDomain ad = param->ad;

        if (param->ignore_user_cache_id == false)
        {
            param->user_index++;

            if (param->user_index >= p1_neg->num_user_certificate_ids)
            {
                /* We have tried searching with all certificates the peer sent
                   us. Restart from the first cache id. */
                param->user_index = 0;

                /* We have tried this CA. Move to next CA. */
                param->ca_index++;

                /* We have tried all CA's. Do search without user cache ID's
                   (with all possible CA's). */
                if (param->ca_index >= ad->num_cas)
                {
                    param->ca_index = 0;
                    param->ignore_user_cache_id = true;
                }
            }
        }
        else
        {
            /* We have tried this CA. Move to next CA. */
            param->ca_index++;

            /* Have we tried all available CA's? */
            if (param->ca_index >= ad->num_cas)
            {
                proceed = false;
            }
        }
    }

    param->validation_round_count++;

    return proceed;
}

static void
pm_ike_certs_remote_validation_done(
        struct SshPmIkeCMParam *param)
{
    /* Print log only if there has been several validation rounds which
       means that there has been failure in some point. */
    if (param->validation_round_count > 1)
    {
        pm_ike_certs_remote_validation_progress(param, true);
    }
}

static void
pm_ike_certs_remote_validation_complete(
        bool success)
{
    if (success == true)
    {
        ssh_log_event(
                SSH_LOGFACILITY_LOCAL0,
                SSH_LOG_INFORMATIONAL,
                "Remote certificate validation successful");
    }
    else
    {
        ssh_log_event(
                SSH_LOGFACILITY_LOCAL0,
                SSH_LOG_INFORMATIONAL,
                "Remote certificate validation failed");
    }
}

static void
pm_ike_certs_local_validation_progress(
        struct SshPmIkeCMParam *param,
        bool success)
{
    SshLogFacility facility = SSH_LOGFACILITY_LOCAL0;
    SshIkev2PayloadID payload_id = param->ee_key;
    SshPmAuthDomain ad = param->ad;
    SshPmP1 p1 = param->p1;
    SshPmP1Negotiation p1_neg = p1->n;
    SshCMCertificate local_cert;
    char *result_string;

    if (p1_neg == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("IKE negotiation not active, cannot log validation process"));
        return;
    }

    if (success == true)
    {
        result_string = "succeeded";
    }
    else
    {
        result_string = "failed";
    }

    local_cert = pm_ike_certs_get_local_cert(param);

    if (param->p1_ca_index < p1_neg->crs.num_cas)
    {
        struct SshPmCertRequestInfo cert_request_info = { 0 };

#ifdef SSHDIST_IKEV1
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        {
            cert_request_info.is_ikev1 = true;
        }
#endif /* SSHDIST_IKEV1 */

        cert_request_info.request = p1_neg->crs.cas[param->p1_ca_index];
        cert_request_info.len =  p1_neg->crs.ca_lens[param->p1_ca_index];

        if (local_cert != NULL)
        {
            ssh_log_event(
                    facility,
                    SSH_LOG_INFORMATIONAL,
                    "Validation %s for local identity '%@' and "
                    "local certificate %@ against certificate request '%@'",
                    result_string,
                    ssh_pm_ike_id_render, payload_id,
                    pm_ike_certs_render, local_cert,
                    pm_ike_certs_request_render, &cert_request_info);
        }
        else
        {
            ssh_log_event(
                    facility,
                    SSH_LOG_INFORMATIONAL,
                    "Validation %s for local identity '%@' and "
                    "against certificate request '%@'",
                    result_string,
                    ssh_pm_ike_id_render, payload_id,
                    pm_ike_certs_request_render, &cert_request_info);
        }
    }
    else
    if (param->ca_index < ad->num_cas)
    {
        if (local_cert != NULL)
        {
            ssh_log_event(
                    facility,
                    SSH_LOG_INFORMATIONAL,
                    "Validation %s for local identity '%@' and "
                    "local certificate %@ against trust anchor %@",
                    result_string,
                    ssh_pm_ike_id_render, payload_id,
                    pm_ike_certs_render, local_cert,
                    pm_ike_certs_render, pm_ike_certs_get_ca_cert(param));
        }
        else
        {
            ssh_log_event(
                    facility,
                    SSH_LOG_INFORMATIONAL,
                    "Validation %s for local identity '%@' and "
                    "against trust anchor %@",
                    result_string,
                    ssh_pm_ike_id_render, payload_id,
                    pm_ike_certs_render, pm_ike_certs_get_ca_cert(param));
        }
    }
    else
    if (param->ca_index == ad->num_cas)
    {
        if (local_cert != NULL)
        {
            ssh_log_event(
                    facility,
                    SSH_LOG_INFORMATIONAL,
                    "Validation %s for local identity '%@' and "
                    "local certificate %@",
                    result_string,
                    ssh_pm_ike_id_render, payload_id,
                    pm_ike_certs_render, local_cert);
        }
        else
        {
            ssh_log_event(
                    facility,
                    SSH_LOG_INFORMATIONAL,
                    "Validation %s for local identity '%@'",
                    result_string,
                    ssh_pm_ike_id_render, payload_id);
        }
    }
}

static void
pm_ike_certs_local_error(
        struct SshPmIkeCMParam *param,
        const char *error_string)
{
    pm_ike_certs_local_validation_progress(param, false);

    ssh_log_event(
            SSH_LOGFACILITY_LOCAL0,
            SSH_LOG_INFORMATIONAL,
            "Reason: %s",
            error_string);
}

static void
pm_ike_certs_local_validator_error(
        struct SshPmIkeCMParam *param,
        SshCMSearchInfo info)
{
    pm_ike_certs_local_validation_progress(param, false);

    pm_ike_certs_validator_error(info);
}

static void
pm_ike_certs_local_validation_start(
        struct SshPmIkeCMParam *param)
{
    param->validation_round_count = 0;

    ssh_log_event(
            SSH_LOGFACILITY_LOCAL0,
            SSH_LOG_INFORMATIONAL,
            "Local certificate validation started");
}

static bool
pm_ike_certs_is_already_checked(
        SshPmP1 p1,
        unsigned char *kid,
        size_t kid_len)
{
    int i;

    SSH_ASSERT(kid_len == 20); /* Length of SHA1 hash */

#ifdef SSHDIST_IKEV1
    if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0)
#endif /* SSHDIST_IKEV1 */
    {
        SshPmP1Negotiation p1_neg = p1->n;

        for (i = 0; i < p1_neg->crs.num_cas; i++)
        {
            /* Have we already looked at this? */
            if (memcmp(kid, p1_neg->crs.cas[i], kid_len) == 0)
            {
                /* Yes we have. */
                return true;
            }
        }
    }

    return false;
}

static bool
pm_ike_certs_local_validation_continue(
        struct SshPmIkeCMParam *param,
        SshPmP1 p1,
        SshCMSearchConstraints *ca_constraints_p,
        SshIkev2Error *error_code_p)
{
    SshCMSearchConstraints ca_constraints = NULL;
    bool set_ca_constraints = false;
    SshCertDBKey *ca_keys = NULL;
    SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
    SshPmAuthDomain ad = param->ad;
    SshPmP1Negotiation p1_neg = p1->n;
    bool proceed;

    if (p1_neg == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("IKE negotiation not active, cannot continue validation"));

        pm_ike_certs_local_error(
                param,
                "Validation cancelled, IKE negotiation not active anymore");
        return false;
    }

    /* Don't increment index if this is the first round. */
    if (param->validation_round_count != 0)
    {
        /* Increment correct variable we are looking for at the current. */
        if (param->p1_ca_index < p1_neg->crs.num_cas)
        {
            param->p1_ca_index++;
        }
        else
        {
            param->ca_index++;
        }
    }

    /* First try looking with CA's provided by the other end. */
    if (param->p1_ca_index < p1_neg->crs.num_cas)
    {
        int index = param->p1_ca_index;

#ifdef SSHDIST_IKEV1
        if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        {
            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("IKEv1 CA selection index %d",
                     index));

            if (ssh_cm_key_set_dn(
                        &ca_keys,
                        p1_neg->crs.cas[index],
                        p1_neg->crs.ca_lens[index])
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set DN"));

                pm_ike_certs_local_error(
                        param,
                        "Validation cancelled, Cannot allocate memory");

                proceed = false;
            }
            else
            {
                set_ca_constraints = true;
                proceed = true;
            }
        }
        else
#endif /* SSHDIST_IKEV1 */
        {
            SSH_DEBUG(
                    SSH_D_NICETOKNOW,
                    ("IKEv2 CA selection index %d",
                     index));

            SSH_ASSERT(p1_neg->crs.ca_lens[index] == 20);
            /* Set KID received from the other end as search criteria. */
            if (ssh_cm_key_set_x509_key_identifier(
                        &ca_keys,
                        p1_neg->crs.cas[index],
                        p1_neg->crs.ca_lens[index])
                == false)
            {
                SSH_DEBUG(
                        SSH_D_FAIL,
                        ("Could not set x509 key identifier"));

                pm_ike_certs_local_error(
                        param,
                        "Validation cancelled, Cannot allocate memory");

                proceed = false;
            }
            else
            {
                set_ca_constraints = true;
                proceed = true;
            }
        }
    }
    else
    if (param->ca_index < ad->num_cas)
    {
        unsigned char *kid = NULL;
        size_t kid_len;

        while (param->ca_index < ad->num_cas)
        {
            /* Ok, now we set our CA's as search criteria using KID. */
            kid =
                pm_ike_certs_compute_key_id(
                        ad->cas[param->ca_index],
                        &kid_len);
            if (kid == NULL)
            {
                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
                break;
            }

            /* Have we already looked at this? */
            if (pm_ike_certs_is_already_checked(p1, kid, kid_len) == true)
            {
                /* Yes we have, skip it and get to the next one. */
                ssh_free(kid);
                kid = NULL;

                SSH_DEBUG(
                        SSH_D_NICETOKNOW,
                        ("Skip CA with index %d from authentication domain",
                         param->ca_index));

                param->ca_index++;
                continue;
            }

            /* found next */
            break;
        }

        if (error_code == SSH_IKEV2_ERROR_OK)
        {
            if (kid != NULL)
            {
                SSH_DEBUG(
                        SSH_D_NICETOKNOW,
                        ("Select CA with index %d from authentication domain",
                         param->ca_index));

                if (ssh_cm_key_set_x509_key_identifier(
                            &ca_keys,
                            kid,
                            kid_len)
                    == false)
                {
                    SSH_DEBUG(
                            SSH_D_FAIL,
                            ("Could not set x509 key identifier"));

                    pm_ike_certs_local_error(
                            param,
                            "Validation cancelled, Cannot allocate memory");

                    proceed = false;
                }
                else
                {
                    set_ca_constraints = true;
                    proceed = true;
                }

                ssh_free(kid);
            }
            else
            {
                proceed = true;
            }
        }
        else
        {
            proceed = false;
        }
    }
    else
    if (param->ca_index == ad->num_cas)
    {
        /* Overloading of ca_index for free search. This is done if all
           other possibilities fail. */
        proceed = true;
    }
    else
    {
        /* Have we tried all available CA's.
           Break out, we have done everything we can. */

        SSH_DEBUG(SSH_D_NICETOKNOW, ("All available CAs validated"));

        proceed = false;
    }

    if (proceed == true)
    {
        if (set_ca_constraints == true)
        {
            SSH_ASSERT(ca_keys != NULL);

            /* Set up search constraints for ca certificate */
            ca_constraints = ssh_cm_search_allocate();

            if (ca_constraints == NULL)
            {
                SSH_DEBUG(
                        SSH_D_FAIL,
                        ("Could not allocate search constraints"));

                pm_ike_certs_local_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
                proceed = false;
            }
            else
            {
                ssh_cm_search_set_keys(ca_constraints, ca_keys);
                param->create_path = true;
            }
        }
        else
        {
            SSH_ASSERT(ca_keys == NULL);

            SSH_DEBUG(SSH_D_NICETOKNOW, ("All CAs validated, try without CA"));

            param->create_path = false;
        }
    }

    if (proceed == true)
    {
        param->validation_round_count++;
    }

    *ca_constraints_p = ca_constraints;
    *error_code_p = error_code;

    return proceed;
}

static void
pm_ike_certs_local_validation_done(
        struct SshPmIkeCMParam *param)
{
    /* Print log only if there has been several validation rounds which
       means that there has been failure in some point. */
    if (param->validation_round_count > 1)
    {
        pm_ike_certs_local_validation_progress(param, true);
    }
}

static void
pm_ike_certs_local_validation_complete(
        bool success)
{
    if (success == true)
    {
        ssh_log_event(
                SSH_LOGFACILITY_LOCAL0,
                SSH_LOG_INFORMATIONAL,
                "Local certificate validation successful");
    }
    else
    {
        ssh_log_event(
                SSH_LOGFACILITY_LOCAL0,
                SSH_LOG_INFORMATIONAL,
                "Local certificate validation failed");
    }
}


/***************************** PAD Certificate Handling **********************/

/***************************** Get Certificate Authorities *******************/

SshOperationHandle
ssh_pm_ike_get_cas(
        SshSADHandle sad_handle,
        SshIkev2ExchangeData ed,
        SshIkev2PadGetCAsCB reply_callback,
        void *reply_callback_context)
{
    SshPm pm = sad_handle->pm;
    SshPmP1 p1 = (SshPmP1)ed->ike_sa;
    SshPmP1Negotiation p1_neg = p1->n;
    SshPmAuthDomain ad = NULL;
    SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
    SshIkev2CertEncoding ca_encoding = SSH_IKEV2_CERT_X_509;
    uint32_t num_cas;
    int i;

    /* If policymanager is not in active state, we wan't to reject this. */
    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
        SSH_DEBUG(SSH_D_FAIL, ("PM is not active when trying to get CAs"));
        error_code = SSH_IKEV2_ERROR_SUSPENDED;
        goto error;
    }

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
        SSH_DEBUG(SSH_D_FAIL, ("PM is going down when trying to get CAs"));
        error_code = SSH_IKEV2_ERROR_GOING_DOWN;
        goto error;
    }

    /* Ignore request if not in IKE SA negotiation phase. */
    if (p1_neg == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Ignoring get certificate authorities request received "
                 "outside IKE negotiation"));
        goto error;
    }

    SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
    SSH_PM_ASSERT_P1N(p1);

    if (p1_neg->ed == NULL)
    {
        p1_neg->ed = ed;
    }

    /* Verify correct authentication domain */
    if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    {
        goto error;
    }
    else
    {
        ad = p1->auth_domain;
    }

    num_cas = ad->num_cas;
    if (num_cas == 0)
    {
        goto error;
    }

#ifdef SSHDIST_IKEV1
    /* For IKEv1 SA's return the Distinguished Name encoding of the Issuer
       Name of the X.509 certificate authority to the IKE library. */
    if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
        SshIkev2CertEncoding *ca_encodings = NULL;
        const unsigned char **ca = NULL;
        size_t *ca_len = NULL;

        ca_encodings = ssh_calloc(num_cas, sizeof(SshIkev2CertEncoding));
        ca = ssh_calloc(num_cas, sizeof(unsigned char *));
        ca_len = ssh_calloc(num_cas, sizeof(size_t));

        if (!ca_encodings || !ca || !ca_len)
        {
            ssh_free(ca_encodings);
            ssh_free(ca);
            ssh_free(ca_len);
            goto error;
        }

        for (i = 0; i < num_cas; i++)
        {
            SshPmCa authority = ad->cas[i];

            ca_encodings[i] = SSH_IKEV2_CERT_X_509;
            ca[i] = authority->cert_issuer_dn;
            ca_len[i] = authority->cert_issuer_dn_len;
        }

        SSH_DEBUG(
                SSH_D_MIDOK,
                ("Returning %d CA's for IKEv1 SA to the IKE library",
                 num_cas));

        (*reply_callback)(
                SSH_IKEV2_ERROR_OK,
                num_cas,
                ca_encodings,
                ca,
                ca_len,
                reply_callback_context);

        ssh_free(ca_encodings);
        ssh_free(ca);
        ssh_free(ca_len);
        return NULL;
    }
#endif /* SSHDIST_IKEV1 */

    {
        const unsigned char *ca_authority_data;
        size_t ca_authority_size;
        SshBufferStruct buffer[1];

        /* Compute authority data */
        ssh_buffer_init(buffer);
        for (i = 0; i < num_cas; i++)
        {
            SshPmCa ca = ad->cas[i];
            unsigned char *kid;
            size_t kid_len;

            kid = pm_ike_certs_compute_key_id(ca, &kid_len);
            if (kid == NULL)
            {
                ssh_buffer_uninit(buffer);
                error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
                goto error;
            }

            if (ssh_buffer_append(buffer, kid, kid_len) != SSH_BUFFER_OK)
            {
                goto error;
            }

            ssh_free(kid);
        }

        ca_authority_data = ssh_buffer_ptr(buffer);
        ca_authority_size = ssh_buffer_len(buffer);

        if (ca_authority_size == 0)
        {
            ssh_buffer_uninit(buffer);
            error_code = SSH_IKEV2_ERROR_OK;
            goto error;
        }

        (*reply_callback)(
                SSH_IKEV2_ERROR_OK,
                1,
                &ca_encoding,
                &ca_authority_data,
                &ca_authority_size,
                reply_callback_context);

        ssh_buffer_uninit(buffer);
    }

    return NULL;

   error:
    (*reply_callback)(
            error_code,
            0,
            NULL,
            NULL,
            NULL,
            reply_callback_context);

    return NULL;
}

/***************************** Get Certificates ******************************/




#define MAX_CERT_PATH_LEN 16

#ifdef SSHDIST_HTTP_SERVER

struct SshPmCertAccessEntry
{
    SshADTMapHeaderStruct adt_header;
    int ttl;
    unsigned char *data;
    size_t len;
    char pattern[8];
};

static void
pm_cert_access_timer(
        void *context)
{
    SshPm pm = context;
    SshADTHandle handle;
    struct SshPmCertAccessEntry *entry;
    struct SshPmCertAccessEntry *next;

    for (handle = ssh_adt_enumerate_start(pm->cert_access.server_db);
         handle != SSH_ADT_INVALID;
         handle = next)
    {
        next = ssh_adt_enumerate_next(pm->cert_access.server_db, handle);

        entry = ssh_adt_get(pm->cert_access.server_db, handle);
        if (--entry->ttl > 0)
        {
            continue;
        }

        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Unregistered pattern \"%@\"",
                 ssh_safe_text_render, entry->pattern));

        ssh_adt_delete(pm->cert_access.server_db, handle);
    }

    if (ssh_adt_num_objects(pm->cert_access.server_db) != 0)
    {
        ssh_register_timeout(
                &pm->cert_access.timeout,
                10L,
                0L,
                pm_cert_access_timer,
                pm);
    }
}

/* Provide access to 'data' behind url path 'pattern' for some
   time. */
static bool
pm_cert_access_register_object(
        SshPm pm,
        char *pattern,
        const unsigned char *data,
        size_t len)
{
    struct SshPmCertAccessEntry *entry;
    struct SshPmCertAccessEntry probe;
    bool rv = false;
    SshADTHandle handle;

    /* Probe for pattern. If found, set full lifetime. If not found, add
       with full lifetime. */

    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("Register pattern \"%@\" with %d bytes of data",
             ssh_safe_text_render, pattern,
             len));

    memcpy(probe.pattern, pattern, sizeof(probe.pattern));

    handle = ssh_adt_get_handle_to_equal(pm->cert_access.server_db, &probe);
    if (handle != SSH_ADT_INVALID)
    {
        entry = ssh_adt_get(pm->cert_access.server_db, handle);
        entry->ttl = 6;
        rv = true;
    }
    else
    {
        entry = ssh_calloc(1, sizeof(*entry));
        if (entry != NULL)
        {
            memcpy(entry->pattern, pattern, sizeof(entry->pattern));
            entry->ttl = 6;
            entry->len = len;

            entry->data = ssh_memdup(data, len);
            if (entry->data != NULL)
            {
                if (ssh_adt_num_objects(pm->cert_access.server_db) == 0)
                {
                    ssh_register_timeout(
                            &pm->cert_access.timeout,
                            10L,
                            0L,
                            pm_cert_access_timer, pm);
                }

                ssh_adt_insert(pm->cert_access.server_db, entry);
                rv = true;
            }
            else
            {
                ssh_free(entry);
            }
        }
    }
    return rv;
}

static bool
pm_cert_access_http_handler(
        SshHttpServerContext http,
        SshHttpServerConnection connection,
        SshStream stream,
        void *context)
{
    const char *uri;
    struct SshPmCertAccessEntry probe;
    struct SshPmCertAccessEntry *entry;
    SshBuffer buffer;
    SshADTHandle handle;
    SshPm pm = context;

    uri = ssh_http_server_get_uri(connection);

    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("Request for URL \"%@\"",
             ssh_safe_text_render, uri));

    if (uri && *uri == '/')
    {
        uri++;
    }

    if (uri == NULL || strlen(uri) != sizeof(probe.pattern))
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Invalid length %d, expected %d",
                 (uri == NULL ? -1 : strlen(uri)),
                 sizeof(probe.pattern)));

        ssh_http_server_error_not_found(connection);
        ssh_stream_destroy(stream);
        return true;
    }

    memcpy(probe.pattern, uri, sizeof(probe.pattern));
    handle = ssh_adt_get_handle_to_equal(pm->cert_access.server_db, &probe);
    if (handle != SSH_ADT_INVALID)
    {
        buffer = ssh_buffer_allocate();
        if (buffer != NULL)
        {
            entry = ssh_adt_get(pm->cert_access.server_db, handle);

            if (ssh_buffer_append(buffer, entry->data, entry->len)
                == SSH_BUFFER_OK)
            {
                ssh_http_server_set_content_length(connection, entry->len);
                ssh_http_server_send_buffer(connection, buffer);
            }
            else
            {
                SSH_DEBUG(
                        SSH_D_NICETOKNOW,
                        ("Buffer append failed. Cannot send buffer"));

                ssh_buffer_free(buffer);
                buffer = NULL;
            }
        }
    }
    else
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Resource not found"));
        ssh_http_server_error_not_found(connection);
        ssh_stream_destroy(stream);
    }

    return true;
}

static int
pm_cert_access_compare(
        const void *p1,
        const void *p2,
        void *context)
{
    const struct SshPmCertAccessEntry *entry1 = p1;
    const struct SshPmCertAccessEntry *entry2 = p2;

    return memcmp(entry1->pattern, entry2->pattern, sizeof(entry1->pattern));
}

static uint32_t
pm_cert_access_hash(
        const void *p,
        void *context)
{
    const struct SshPmCertAccessEntry *entry = p;
    uint32_t hash = 0, i;

    for (i = 0; i < sizeof(entry->pattern); i++)
    {
        hash += entry->pattern[i];
        hash += hash << 10;
        hash ^= hash >> 6;
    }

    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;

    return hash;
}

static void
pm_cert_access_destroy(
        void *p,
        void *context)
{
    struct SshPmCertAccessEntry *entry = p;
    ssh_free(entry->data);
    ssh_free(entry);
}

static void
pm_cert_access_server_stop(
        SshPm pm)
{
    ssh_cancel_timeout(&pm->cert_access.timeout);

    if (pm->cert_access.server_db)
    {
        ssh_adt_destroy(pm->cert_access.server_db);
    }
    pm->cert_access.server_db = NULL;

    if (pm->cert_access.server)
    {
        ssh_http_server_stop(pm->cert_access.server, NULL_FNPTR, NULL);
    }
    pm->cert_access.server = NULL;
}

bool
ssh_pm_cert_access_server_start(
        SshPm pm,
        uint16_t port,
        uint32_t flags)
{
    SshHttpServerParams params;
    char portbuf[8];

    /* If port has changed, restart server and flush all pending
       entries. The remote can no longer find them as she has wrong
       port. */
    if (pm->cert_access.server != NULL
        && pm->cert_access.server_port != port)
    {
        pm_cert_access_server_stop(pm);
    }

    if (pm->cert_access.server == NULL)
    {
        pm->cert_access.server_db =
            ssh_adt_create_generic(
                    SSH_ADT_BAG,
                    SSH_ADT_HEADER,
                    SSH_ADT_OFFSET_OF(
                            struct SshPmCertAccessEntry,
                            adt_header),
                    SSH_ADT_HASH, pm_cert_access_hash,
                    SSH_ADT_COMPARE, pm_cert_access_compare,
                    SSH_ADT_DESTROY, pm_cert_access_destroy,
                    SSH_ADT_ARGS_END);
        if (pm->cert_access.server_db == NULL)
        {
            return false;
        }

        memset(&params, 0, sizeof(params));
        ssh_snprintf(portbuf, sizeof(portbuf), "%d", (unsigned int)port);
        params.port = portbuf;

        pm->cert_access.server = ssh_http_server_start(&params);
        if (pm->cert_access.server == NULL)
        {
            pm_cert_access_server_stop(pm);
            return false;
        }

        ssh_http_server_set_handler(
                pm->cert_access.server,
                "*",
                0,
                pm_cert_access_http_handler,
                pm);
        pm->cert_access.server_port = port;

        if (flags & SSH_PM_CERT_ACCESS_SERVER_FLAGS_SEND_BUNDLES)
        {
            pm->cert_access.send_certificate_bundles = true;
        }
    }

    return true;
}

void
ssh_pm_cert_access_server_stop(
        SshPm pm)
{
    pm_cert_access_server_stop(pm);
    return;
}

static int
pm_ike_get_certificates_makeurl(
        char *url,
        size_t url_len,
        SshPm pm,
        SshPmP1 p1,
        const char *path)
{
    bool is6 = SSH_IP_IS6(p1->ike_sa->server->ip_address);
    SshIpAddrStruct ip;
    struct SshPmCertAccessEntry probe;
    int rv;

    ip = p1->ike_sa->server->ip_address[0];
#ifdef WITH_IPV6
    if (is6)
    {
        SSH_IP6_SCOPE_ID(&ip) = 0;
    }
#endif /* WITH_IPV6 */

    /* Truncate the hash into N first characters (the amount derived
       from the struct SshPmCertAccessEntry definition */
    rv =
        ssh_snprintf(
                url,
                url_len,
                "http://%s%@%s:%d/%*s",
                is6 ? "[" : "",
                ssh_ipaddr_render, &ip,
                is6 ? "]" : "",
                pm->cert_access.server_port,
                sizeof(probe.pattern),
                path);
    return rv;
}


/* This function finalizes the certificate payload. It considers the
   local configuration and peers capabilities, and either sends
   certificates within IKE packets, or publishes them separately / or
   as a bundle on a local web server (and modifies the inputs
   accordingly).

   If memory allocation fails here, indicate it up to the caller, so
   recovery (drop of this negotiation likely) can be taken. */
static bool
pm_ike_get_certificates_finalize(
        SshPm pm,
        SshPmP1 p1,
        size_t *nof_certs,
        SshIkev2CertEncoding *cert_encodings,
        unsigned char **cert_bers,
        size_t *cert_lens)
{
    SshHash sha1 = NULL;
    unsigned char digest[20], *data;
    char url[256], path[2 * sizeof(digest)];
    SshPmP1Negotiation p1_neg = p1->n;
    size_t len;
    int url_len, i;

    /* If http access is not supported by either end, we are already
       done */
    if (!p1_neg->cert_access_supported || !pm->cert_access.server)
    {
        return true;
    }

    if (ssh_hash_allocate("sha1", &sha1) != SSH_CRYPTO_OK)
    {
        goto error;
    }

    if (pm->cert_access.send_certificate_bundles)
    {
        SshAsn1Context asn1 = NULL;
        SshAsn1Node datanode, node, list;

        asn1 = ssh_asn1_init();
        if (asn1 == NULL)
        {
            goto error;
        }

        list = NULL;
        for (i = 0; i < *nof_certs; i++)
        {
            if (ssh_asn1_decode_node(
                        asn1,
                        cert_bers[i],
                        cert_lens[i],
                        &datanode)
                == SSH_ASN1_STATUS_OK)
            {
                if (ssh_asn1_create_node(
                            asn1,
                            &node,
                            "(any (e 0))",
                            datanode)
                    == SSH_ASN1_STATUS_OK)
                {
                    list = ssh_asn1_add_list(list, node);
                }
            }
            ssh_free(cert_bers[i]);
            cert_bers[i] = NULL; /* must be cleared for error */
        }

        if (list)
        {
            data = NULL;
            if (ssh_asn1_create_node(
                        asn1,
                        &node,
                        "(sequence () (any ()))",
                        list)
                != SSH_ASN1_STATUS_OK
                || ssh_asn1_encode_node(asn1, node) != SSH_ASN1_STATUS_OK
                || ssh_asn1_node_get_data(node, &data, &len)
                != SSH_ASN1_STATUS_OK)
            {
              bundle_error:
                ssh_free(data);
                ssh_asn1_free(asn1);
                goto error;
            }

            ssh_hash_update(sha1, data, len);
            if (ssh_hash_final(sha1, digest) != SSH_CRYPTO_OK)
            {
                goto bundle_error;
            }

            ssh_snprintf(
                    path,
                    sizeof(path),
                    "%.*@",
                    sizeof(digest),
                    ssh_hex_render, digest);
            path[8] = '\0';

            url_len =
                 pm_ike_get_certificates_makeurl(
                         url,
                         sizeof(url),
                         pm,
                         p1,
                         path);
            if (url_len == -1)
            {
                goto bundle_error;
            }

            cert_encodings[0] = SSH_IKEV2_CERT_HASH_AND_URL_X509_BUNDLE;
            cert_lens[0] = sizeof(digest) + url_len;

            cert_bers[0] = ssh_malloc(sizeof(digest) + url_len);
            if (cert_bers[0] == NULL)
            {
                goto bundle_error;
            }

            memcpy(cert_bers[0], digest, sizeof(digest));
            memcpy(cert_bers[0] + sizeof(digest), url, url_len);

            if (!pm_cert_access_register_object(pm, path, data, len))
            {
                goto bundle_error;
            }

            ssh_free(data);

            *nof_certs = 1;
        }
        ssh_asn1_free(asn1);
    }
    else
    {
        for (i = 0; i < *nof_certs; i++)
        {
            ssh_hash_reset(sha1);
            ssh_hash_update(sha1, cert_bers[i], cert_lens[i]);
            if (ssh_hash_final(sha1, digest) != SSH_CRYPTO_OK)
            {
                goto error;
            }

            ssh_snprintf(
                    path,
                    sizeof(path),
                    "%.*@",
                    sizeof(digest),
                    ssh_hex_render, digest);
            path[8] = '\000';

            url_len =
                pm_ike_get_certificates_makeurl(
                        url,
                        sizeof(url),
                        pm,
                        p1,
                        path);
            if (url_len == -1)
            {
                goto error;
            }

            data = cert_bers[i];
            len = cert_lens[i];

            cert_encodings[i] = SSH_IKEV2_CERT_HASH_AND_URL_X509;
            cert_lens[i] = sizeof(digest) + url_len;

            cert_bers[i] = ssh_malloc(sizeof(digest) + url_len);
            if (cert_bers[i] == NULL)
            {
                ssh_free(data);
                goto error;
            }

            memcpy(cert_bers[i], digest, sizeof(digest));
            memcpy(cert_bers[i] + sizeof(digest), url, url_len);

            if (!pm_cert_access_register_object(pm, path, data, len))
            {
                ssh_free(data);
                goto error;
            }
            ssh_free(data);
        }
    }

    ssh_hash_free(sha1);
    return true;

   error:
    if (sha1)
    {
        ssh_hash_free(sha1);
    }

    for (i = 0; i < *nof_certs; i++)
    {
        ssh_free(cert_bers[i]);
    }
    *nof_certs = 0;
    return false;
}
#endif /* SSHDIST_HTTP_SERVER */

/* Callback function for find_path operation */
static void
pm_ike_get_certificates_find_path_cb(
        void *context,
        SshCMSearchInfo info,
        SshCMCertList list)
{
    struct SshPmIkeCMParam *param = context;
    SshPm pm = param->sad_handle->pm;
    SshPmEk ek = NULL;
    SshPrivateKey private_key_out = NULL;
    SshIkev2CertEncoding cert_encodings[MAX_CERT_PATH_LEN];
    unsigned char *cert_bers[MAX_CERT_PATH_LEN];
    size_t cert_lens[MAX_CERT_PATH_LEN], nof_certs = 0;
    SshCMCertificate cert = NULL;
    SshPmP1 p1 = param->p1;
    SshPmP1Negotiation p1_neg = p1->n;
    SshPmTunnel tunnel = NULL;
    SshCMContext cm = param->ad->cm;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Return with status %u, success %s",
             info->status,
             info->status == SSH_CM_STATUS_OK ? "Yes" : "No"));

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("PM is going down when receiving validator CB"));
        param->error_code = SSH_IKEV2_ERROR_GOING_DOWN;

        pm_ike_certs_local_error(param, "Certificate validation cancelled");
        goto error;
    }

    /* Check if validator has been stoppped. */
    if (info->status == SSH_CM_STATUS_STOPPED)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Validator has been stoppped"));
        param->error_code = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;

        pm_ike_certs_local_error(param, "Certificate validation cancelled");
        goto error;
    }

    /* An error occurred */
    if (info->status != SSH_CM_STATUS_OK)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Certificate path construction failed"));

        param->error_code = SSH_IKEV2_ERROR_OK;

        /* Handle error received from validator. */
        pm_ike_certs_local_validator_error(param, info);

        goto error;
    }

    tunnel = ssh_pm_p1_get_tunnel(pm, p1);
    if (tunnel == NULL || p1_neg == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("No tunnel available."));
        param->error_code = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;

        pm_ike_certs_local_error(param, "Tunnel not available");
        goto error;
    }

    if (tunnel->u.ike.local_cert_kid != NULL)
    {
        SshCMCertificate cmcert = pm_ike_certs_get_local_cert(param);

        /* Get the private key for end entity. Lookup by the given
           certificate. */
        if (cmcert)
        {
            ek = ssh_pm_ek_get_by_cert(pm, cmcert);
        }
    }
    else
    {
        SshCMCertificate cmcert;

        cmcert = ssh_cm_cert_list_last(list);
        if (cmcert)
        {
            ek = ssh_pm_ek_get_by_cert(pm, cmcert);
        }
    }

    /* No private key available */
    if (ek == NULL ||
        (ek->accel_private_key == NULL && ek->private_key == NULL))
    {
        SSH_DEBUG(SSH_D_FAIL, ("No private key available"));
        param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;

        pm_ike_certs_local_error(param, "Private key not available");
        goto error;
    }

    /* Use accelerated private key if available, otherwise use software key. */
    if (!ek->accel_private_key ||
        ssh_private_key_copy(
                ek->accel_private_key,
                &private_key_out)
        != SSH_CRYPTO_OK)
    {
        if (!ek->private_key ||
            ssh_private_key_copy(
                    ek->private_key,
                    &private_key_out)
            != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Unable to copy private key"));

            param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;

            pm_ike_certs_local_error(param, "Cannot copy private key");
            goto error;
        }
    }

    /* Set proper scheme */
    if (ek->rsa_key)
    {
        const char *rsa_scheme = NULL;

        /* Use signature algorithm in certificate as a hint */
        if ((pm->params.enable_key_restrictions &
             SSH_PM_PARAM_ALGORITHMS_NIST_800_131A) != 0)
        {
            SshCMCertificate tmp_cert = NULL;
            SshX509Certificate x509_cert = NULL;

            if ((tunnel->u.ike.algorithms &
                 (SSH_PM_MAC_HMAC_MD5 | SSH_PM_MAC_HMAC_SHA1)) != 0 &&
                (tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1) != 0)
            {
                SSH_DEBUG(
                        SSH_D_ERROR,
                        ("Algorithm restrictions enforced: SHA1 and MD5 as "
                         "signing algorithm for IKEv1 not allowed"));

                pm_ike_certs_local_error(
                        param,
                        "Algorithm restrictions enforced for RSA");

                param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
                goto error;
            }

            if (list != NULL && !ssh_cm_cert_list_empty(list))
            {
                tmp_cert = ssh_cm_cert_list_last(list);
                if (tmp_cert == NULL ||
                    ssh_cm_cert_get_x509(tmp_cert, &x509_cert) !=
                    SSH_CM_STATUS_OK)
                {
                    SSH_DEBUG(
                            SSH_D_ERROR,
                            ("Getting X.509 certificate from CM certificate "
                             "failed. Unable to set RSA private key scheme"));

                    pm_ike_certs_local_error(param, "Cannot get certificate");

                    param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
                    goto error;
                }
            }
            else
            {
                SSH_DEBUG(
                        SSH_D_ERROR,
                        ("Certificates not available. Unable to set RSA "
                         "private key scheme"));

                pm_ike_certs_local_error(param, "Certificates not available");

                param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
                goto error;
            }

            if (ssh_cm_cert_allowed_algorithms(cm, x509_cert)
                == SSH_CM_STATUS_OK)
            {
                rsa_scheme = ssh_x509_find_signature_algorithm(x509_cert);
            }
            else
            {
                SSH_DEBUG(
                        SSH_D_FAIL,
                        ("Unable to set RSA private key scheme"));

                pm_ike_certs_local_error(
                        param,
                        "Unable to set RSA private key scheme");

                ssh_x509_cert_free(x509_cert);
                param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
                goto error;
            }
            ssh_x509_cert_free(x509_cert);
        }
        else
        {
            rsa_scheme = "rsa-pkcs1-sha1";
        }

        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Using scheme: %s",
                 rsa_scheme));

        if (ssh_private_key_select_scheme(
                    private_key_out,
                    SSH_PKF_SIGN,
                    rsa_scheme,
                    SSH_PKF_END)
            != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Unable to set RSA private key scheme"));

            pm_ike_certs_local_error(
                    param,
                    "Unable to set RSA private key scheme");

            param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
            goto error;
        }

        p1->local_auth_method = SSH_PM_AUTH_RSA;
    }
    else
    if (ek->dsa_key)
    {
        if ((pm->params.enable_key_restrictions &
             SSH_PM_PARAM_ALGORITHMS_NIST_800_131A) != 0)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Algorithm restrictions enforced for DSA"));

            pm_ike_certs_local_error(
                    param,
                    "Algorithm restrictions enforced for DSA");

            param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
            goto error;
        }

        if (ssh_private_key_select_scheme(
                    private_key_out,
                    SSH_PKF_SIGN,
                    "dsa-nist-sha1",
                    SSH_PKF_END)
            != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Unable to set DSA private key scheme"));

            pm_ike_certs_local_error(
                    param,
                    "Unable to set DSA private key scheme");

            param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
            goto error;
        }
        p1->local_auth_method = SSH_PM_AUTH_DSA;
    }
#ifdef SSHDIST_CRYPT_ECP
    else
    if (ek->ecdsa_key)
    {
        const char *scheme = NULL;

        if (ssh_pm_get_key_scheme(
                    ek->public_key,
                    SSH_PM_CM_PUBLIC_KEY,
                    &scheme)
            == false)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Unable to get the applicable key scheme"));

            pm_ike_certs_local_error(
                    param,
                    "Unable to get key scheme for ECDSA");

            param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
            goto error;
        }

        if (ssh_private_key_select_scheme(
                    private_key_out,
                    SSH_PKF_SIGN,
                    scheme,
                    SSH_PKF_END)
            != SSH_CRYPTO_OK)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Unable to set ECDSA private key scheme '%s'",
                     scheme));

            pm_ike_certs_local_error(
                    param,
                    "Unable to set ECDSA private key scheme");

            param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
            goto error;
        }
        p1->local_auth_method = SSH_PM_AUTH_ECP_DSA;
    }
#endif /* SSHDIST_CRYPT_ECP */
    else
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid private key"));

        pm_ike_certs_local_error(param, "Invalid private key type");

        param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
        goto error;
    }

    /* Handle end entity certificate and intermediate CA certificates */
    if (list != NULL && !ssh_cm_cert_list_empty(list))
    {
        unsigned char *ber;
        size_t ber_len;
        SshCMCertificate prev;

        cert = ssh_cm_cert_list_last(list);
        while (cert)
        {
            prev = ssh_cm_cert_list_prev(list);

            if ((prev == NULL && nof_certs > 0)
                || nof_certs >= MAX_CERT_PATH_LEN)
            {
                /* Do allow certificate list to expand too much and do
                   not put the trust anchor certificate into the list. */
                break;
            }

            ber = NULL;
            ber_len = 0;
            if (ssh_cm_cert_get_ber(cert, &ber, &ber_len) != SSH_CM_STATUS_OK)
            {
                SSH_DEBUG(
                        SSH_D_FAIL,
                        ("Unable to convert certificate to x509 ber format"));

                pm_ike_certs_local_error(
                        param,
                        "Unable to convert certificate to x509 ber format");

                param->error_code = SSH_IKEV2_ERROR_CRYPTO_FAIL;
                goto error;
            }

            SSH_ASSERT(ber_len > 0);
            cert_encodings[nof_certs] = SSH_IKEV2_CERT_X_509;

            cert_bers[nof_certs] = ssh_memdup(ber, ber_len);
            if (cert_bers[nof_certs] != NULL)
            {
                cert_lens[nof_certs] = ber_len;
                nof_certs++;
            }
            else
            {
                pm_ike_certs_local_error(param, "Cannot allocate memory");

                param->error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
                goto error;
            }

            /* Break if we are looking for only our end certificate */
            if (!param->create_path || !param->return_path)
            {
                break;
            }

            cert = prev;
        }

#ifdef SSHDIST_HTTP_SERVER
        /* Finalize encodings. */
        if (pm_ike_get_certificates_finalize(
                    pm,
                    p1,
                    &nof_certs,
                    cert_encodings,
                    cert_bers,
                    cert_lens)
            == false)
        {
            pm_ike_certs_local_error(param, "Cannot allocate memory");

            param->error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            goto error;
        }
#endif /* SSHDIST_HTTP_SERVER */
    }
    else
    {
        /* No certificates found, which is perfectly ok */
        SSH_DEBUG(SSH_D_NICETOKNOW, ("No certificates found"));

        pm_ike_certs_local_error(param, "No certificates found");

        param->error_code = SSH_IKEV2_ERROR_OK;
        goto error;
    }

    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("nof_certs = %lu",
             (long unsigned int)nof_certs));

    /* Mark that the search has succeeded */
    param->search_done = true;

    /* Return the certificates and private key to the IKE library. */
    if (!p1->callbacks.aborted)
    {
        if (p1->callbacks.u.get_certificates_cb)
        {
            (*p1->callbacks.u.get_certificates_cb)(
                    SSH_IKEV2_ERROR_OK,
                    private_key_out,
                    nof_certs,
                    cert_encodings,
                    (const unsigned char **) &cert_bers,
                    cert_lens,
                    p1->callbacks.callback_context);
        }

        ssh_operation_unregister_no_free(p1->callbacks.operation);
    }

    /* fall-through to error */
   error:

    while (nof_certs > 0)
    {
        nof_certs--;
        if (cert_bers[nof_certs])
        {
            ssh_free(cert_bers[nof_certs]);
        }
    }

    if (list != NULL)
    {
        ssh_cm_cert_list_free(cm, list);
    }
    if (private_key_out != NULL)
    {
        ssh_private_key_free(private_key_out);
    }

    if (ek != NULL)
    {
        ssh_pm_ek_unref(pm, ek);
    }

    SSH_FSM_CONTINUE_AFTER_CALLBACK(param->thread);
    return;
}

static void
pm_ike_certificate_find_aborted(
        void *context)
{
    struct SshPmIkeCMParam *param = context;

    param->p1->callbacks.u.get_certificates_cb = NULL_FNPTR;
    /* Can not abort CM right now... It will complete and release its
       reference to P1 eventually. Mark operation aborted.  */
    param->p1->callbacks.aborted = true;
}

static void
pm_st_ike_get_certs_destructor(
        SshFSM fsm,
        void *context)
{
    struct SshPmIkeCMParam *param = context;

    pm_ike_certs_param_free(param);
}

static SshIkev2Error
pm_ike_certs_set_local_constraints(
        struct SshPmIkeCMParam *param,
        SshPmTunnel tunnel,
        SshCMSearchConstraints *local_constraints_p)
{
    SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
    SshCMSearchConstraints local_constraints;
    SshCertDBKey *local_keys = NULL;

    /* Set up search constraints for local certificate */
    local_constraints = ssh_cm_search_allocate();
    if (local_constraints == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate search constraints"));

        pm_ike_certs_local_error(param, "Cannot allocate memory");

        error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

    /* Get local identity */
    if (error_code == SSH_IKEV2_ERROR_OK)
    {
        SshIkev2PayloadID payload_id = param->ee_key;

        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("local identity %@",
                 ssh_pm_ike_id_render,
                 payload_id));

        switch (payload_id->id_type)
        {
        case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
        case SSH_IKEV2_ID_TYPE_IPV6_ADDR:

            if (ssh_cm_key_set_ip(
                        &local_keys,
                        payload_id->id_data,
                        payload_id->id_data_size)
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set IP address"));

                pm_ike_certs_local_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }

            break;

        case SSH_IKEV2_ID_TYPE_RFC822_ADDR:

            if (ssh_cm_key_set_email(
                        &local_keys,
                        (char *) payload_id->id_data,
                        payload_id->id_data_size)
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set email"));

                pm_ike_certs_local_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }

            break;

        case SSH_IKEV2_ID_TYPE_FQDN:

            if (ssh_cm_key_set_dns(
                        &local_keys,
                        (char *) payload_id->id_data,
                        payload_id->id_data_size)
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set DNS"));

                pm_ike_certs_local_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }

            break;

        case SSH_IKEV2_ID_TYPE_ASN1_DN:

            if (ssh_cm_key_set_dn(
                        &local_keys,
                        payload_id->id_data,
                        payload_id->id_data_size)
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set DN"));

                pm_ike_certs_local_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }

            break;

        case SSH_IKEV2_ID_TYPE_ASN1_GN:
        case SSH_IKEV2_ID_TYPE_KEY_ID:
        default:

            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Unknown payload id type %d",
                     payload_id->id_type));

            pm_ike_certs_local_error(param, "Unknown payload id type");

            error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
            break;
        }
    }

    if (error_code == SSH_IKEV2_ERROR_OK)
    {
        if (tunnel->u.ike.local_cert_kid != NULL)
        {
            if (ssh_cm_key_set_x509_key_identifier(
                        &local_keys,
                        tunnel->u.ike.local_cert_kid,
                        tunnel->u.ike.local_cert_kid_len)
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set x509 key identifier"));

                pm_ike_certs_local_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }
        }
    }

    if (error_code == SSH_IKEV2_ERROR_OK)
    {
        SshBerTimeStruct start_time;
        SshBerTimeStruct end_time;
        SshTime now;

        ssh_cm_search_set_keys(local_constraints, local_keys);

        /* Require our certificate to be valid now and in near future */
        now = ssh_time();
        ssh_ber_time_set_from_unix_time(&start_time, now);
        ssh_ber_time_set_from_unix_time(&end_time, now + 120);
        ssh_cm_search_set_time(local_constraints, &start_time, &end_time);
#ifdef SSHDIST_IKEV1
        ssh_cm_search_set_key_type(local_constraints, param->key_type);
#endif /* SSHDIST_IKEV1 */
    }

    if (error_code != SSH_IKEV2_ERROR_OK)
    {
        if (local_constraints != NULL)
        {
            ssh_cm_search_free(local_constraints);
            local_constraints = NULL;
        }
    }

    *local_constraints_p = local_constraints;

    return error_code;
}

SSH_FSM_STEP(pm_st_ike_get_certs_find_path);
SSH_FSM_STEP(pm_st_ike_get_certs_failed);
SSH_FSM_STEP(pm_st_ike_get_certs_finish);

SSH_FSM_STEP(pm_st_ike_get_certs_find_path)
{
    struct SshPmIkeCMParam *param = thread_context;
    SshPm pm = param->sad_handle->pm;
    SshCMSearchConstraints local_constraints = NULL;
    SshCMSearchConstraints ca_constraints = NULL;
    SshCMContext cm = param->ad->cm;
    SshIkev2Error error_code;
    SshPmP1 p1 = param->p1;
    SshPmTunnel tunnel;
    bool done = false;
    bool proceed;

    SSH_DEBUG(SSH_D_LOWOK, ("Entering certs find path %d", param->ca_index));

    /* Check for errors from the pm_ike_get_certificates_find_path_cb
       callback. */
    if (param->error_code != SSH_IKEV2_ERROR_OK)
    {
        goto out;
    }

    tunnel = ssh_pm_p1_get_tunnel(pm, p1);
    if (tunnel == NULL)
    {
        goto out;
    }

    /* Has the search operation completed successfully? */
    if (param->search_done)
    {
        pm_ike_certs_local_validation_done(param);

        done = true;
        goto out;
    }

    /* Check if validation process should go to next round. */
    proceed =
        pm_ike_certs_local_validation_continue(
                param,
                p1,
                &ca_constraints,
                &error_code);
    if (proceed == false)
    {
        param->error_code = error_code;
        goto out;
    }

    /* Set up search constraints for local certificate */
    error_code =
        pm_ike_certs_set_local_constraints(
                param,
                tunnel,
                &local_constraints);
    if (error_code != SSH_IKEV2_ERROR_OK)
    {
        SSH_ASSERT(local_constraints == NULL);

        param->error_code = error_code;
        goto out;
    }

    if (param->create_path == true)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("With CA constraints."));

        SSH_FSM_ASYNC_CALL({
                ssh_cm_find_path(
                        cm,
                        ca_constraints,
                        local_constraints,
                        pm_ike_get_certificates_find_path_cb,
                        param);
            });
    }
    else
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("No CA constraints."));

        SSH_FSM_ASYNC_CALL({
                ssh_cm_find(
                        cm,
                        local_constraints,
                        pm_ike_get_certificates_find_path_cb,
                        param);
            });
    }

    SSH_NOTREACHED;

   out:

    if (ca_constraints != NULL)
    {
        ssh_cm_search_free(ca_constraints);
    }

    if (done == true)
    {
        SSH_FSM_SET_NEXT(pm_st_ike_get_certs_finish);
    }
    else
    {
        SSH_FSM_SET_NEXT(pm_st_ike_get_certs_failed);
    }

    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_st_ike_get_certs_failed)
{
    struct SshPmIkeCMParam *param = thread_context;
    SshPmP1 p1 = param->p1;

    /* Inform the IKE library that certificate lookup did not succeed. */
    if (!p1->callbacks.aborted)
    {
        if (p1->callbacks.u.get_certificates_cb)
        {
            (*p1->callbacks.u.get_certificates_cb)(
                    param->error_code,
                    NULL,
                    0,
                    NULL,
                    NULL,
                    NULL,
                    p1->callbacks.callback_context);
        }

        ssh_operation_unregister_no_free(p1->callbacks.operation);
    }

    pm_ike_certs_local_validation_complete(false);

    return SSH_FSM_FINISH;
}

SSH_FSM_STEP(pm_st_ike_get_certs_finish)
{
    pm_ike_certs_local_validation_complete(true);

    return SSH_FSM_FINISH;
}

SshOperationHandle
ssh_pm_ike_get_certificates(
        SshSADHandle sad_handle,
        SshIkev2ExchangeData ed,
        SshIkev2PadGetCertificatesCB reply_callback,
        void *reply_callback_context)
{
    SshPm pm = sad_handle->pm;
    SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
    SshIkev2PayloadID payload_id = NULL;
    struct SshPmIkeCMParam *param = NULL;
    SshPmTunnel tunnel;
    SshPmAuthDomain ad = NULL;
    SshPmP1 p1 = (SshPmP1) ed->ike_sa;
    SshPmP1Negotiation p1_neg;

    SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

    SSH_PM_ASSERT_P1(p1);

    /* If policymanager is not in active state, we wan't to reject this. */
    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
        goto error;
    }

    /* Ignore request if not in IKE SA negotiation phase. */
    p1_neg = p1->n;
    if (p1_neg == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Ignoring get certificates request received outside IKE "
                   "negotiation"));
        goto error;
    }

    if (!p1_neg->tunnel)
    {
        error_code = SSH_IKEV2_ERROR_SA_UNUSABLE;
        goto error;
    }

    /* Verify correct authentication domain */
    if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    {
        goto error;
    }
    else
    {
        ad = p1->auth_domain;
    }

    tunnel = p1_neg->tunnel;
    SSH_ASSERT(ad != NULL);

#ifdef SSHDIST_IKE_EAP_AUTH
    if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
        ad->eap_protocols)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("EAP configured for IKE initiator, "
                                "omitting certificate lookup"));
        error_code = SSH_IKEV2_ERROR_OK;
        goto error;
    }
    if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
        p1_neg->peer_supports_eap_only_auth &&
        (tunnel->flags & SSH_PM_T_EAP_ONLY_AUTH) &&
        ad->eap_protocols)
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Initiator suggested EAP_ONLY_AUTH which is configured for "
                   "the tunnel, omitting certificate lookup"));
        error_code = SSH_IKEV2_ERROR_OK;
        goto error;
    }
#endif /* SSHDIST_IKE_EAP_AUTH */

    /* Return immediately if configuration does not contain any CAs */
    if (ad->num_cas == 0)
    {
        goto error;
    }

    /* Get the local id from the tunnel */
    payload_id = ssh_pm_ike_get_identity(pm, p1, tunnel, false);
    if (payload_id == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Local identity not defined; need to be given "
                 "as 'identity' or 'certificate' at tunnel object"));

        error_code = SSH_IKEV2_ERROR_OK;
        goto error;
    }

    /* IKEv2 key-id is not compatible with x509 key-id. Therefore if local
       identity is of type key-id then there must be a pre-shared key available
       and we will use it. */
    if (payload_id->id_type == SSH_IKEV2_ID_TYPE_KEY_ID)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Local id type is key-id, "
                 "attempting to authenticate using pre-shared key"));

        error_code = SSH_IKEV2_ERROR_OK;
        goto error;
    }

    /* Lookup the preshared key based on our tunnel's local identity if the
       peer has not sent us any certificate requests. If we have a pre-shared
       key available we will use it, if not we will attempt certificate
       lookup. */
    if (p1_neg->crs.num_cas == 0)
    {
        size_t key_len;

        if (ssh_pm_ike_preshared_keys_get_secret(
                    p1->auth_domain,
                    tunnel->local_identity,
                    &key_len)
            != NULL)
        {
            /* Yes, psk is configured. Fall back to psk. */
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Pre-shared key found"));
            error_code = SSH_IKEV2_ERROR_OK;
            goto error;
        }
        SSH_DEBUG(SSH_D_NICETOKNOW, ("No pre-shared key found"));
    }

    /* Allocate context for callback */
    param =
        pm_ike_certs_param_alloc(
                sad_handle,
                p1,
                ad,
                pm_ike_certs_get_key_type(ed),
                payload_id);

    if (param == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate callback context"));
        error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    /* Return only end entity cert or the whole path with intermediate CAs */
    param->return_path = true;
    if ((tunnel->flags & SSH_PM_T_NO_CERT_CHAINS) ||
        (p1->compat_flags & SSH_PM_COMPAT_NO_CERT_CHAINS))
    {
        param->return_path = false;
    }

    SSH_DEBUG(SSH_D_NICETOKNOW, ("Prepare for certificate lookup"));

    pm_ike_certs_local_validation_start(param);

    ssh_fsm_thread_init(
            &pm->fsm,
            &p1_neg->sub_thread,
            pm_st_ike_get_certs_find_path,
            NULL_FNPTR,
            pm_st_ike_get_certs_destructor,
            param);

    ssh_fsm_set_thread_name(&p1_neg->sub_thread, "IKE get certs");

    param->thread = &p1_neg->sub_thread;

    p1->callbacks.aborted = false;
    p1->callbacks.u.get_certificates_cb = reply_callback;
    p1->callbacks.callback_context = reply_callback_context;

    ssh_operation_register_no_alloc(
            p1->callbacks.operation,
            pm_ike_certificate_find_aborted,
            param);

    return p1->callbacks.operation;

   error:
    (*reply_callback)(
            error_code,
            0,
            0,
            NULL,
            NULL,
            NULL,
            reply_callback_context);

    if (payload_id != NULL)
    {
        ssh_pm_ikev2_payload_id_free(payload_id);
    }

    return NULL;
}

/***************************** Get Public Key ********************************/

void
ssh_pm_ike_sa_release_certificates(
        SshPmP1 p1)
{
    SSH_ASSERT(p1 != NULL);

    if (p1->auth_cert != NULL)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Free IKE SA %p auth cert reference",
                 p1));

        ssh_cm_cert_remove_reference(p1->auth_cert);
        p1->auth_cert = NULL;
    }

    if (p1->auth_ca_cert != NULL)
    {
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Free IKE SA %p auth ca cert reference",
                 p1));

        ssh_cm_cert_remove_reference(p1->auth_ca_cert);
        p1->auth_ca_cert = NULL;
    }
}

static void
pm_ike_sa_store_certificates(
        SshPmP1 p1,
        SshCMCertList list)
{
    SshPmP1Negotiation p1_neg = p1->n;
    SshCMCertificate ee_cert;
    SshCMCertificate ca_cert;
    unsigned int ee_cert_id;
    int i;

    /* Store CA certificate */
    ca_cert = ssh_cm_cert_list_first(list);
    SSH_ASSERT(ca_cert != NULL);
    SSH_ASSERT(p1->auth_ca_cert == NULL);
    p1->auth_ca_cert = ca_cert;
    ssh_cm_cert_take_reference(p1->auth_ca_cert);

    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("Take IKE SA %p auth ca cert reference",
             p1));

    /* Store end entity certificate */
    ee_cert = ssh_cm_cert_list_last(list);
    SSH_ASSERT(ee_cert != NULL);
    SSH_ASSERT(p1->auth_cert == NULL);
    p1->auth_cert = ee_cert;
    ssh_cm_cert_take_reference(p1->auth_cert);

    SSH_DEBUG(
            SSH_D_NICETOKNOW,
            ("Take IKE SA %p auth cert reference",
             p1));

    /* Does the chosen ee cert match one of the ee certs the peer sent us? */
    ee_cert_id = ssh_cm_cert_get_cache_id(ee_cert);
    SSH_ASSERT(
            p1_neg->num_user_certificate_ids <= SSH_PM_P1N_NUM_USER_CERT_IDS);
    for (i = 0; i < p1_neg->num_user_certificate_ids; i++)
    {
        if (ee_cert_id == p1_neg->user_certificate_ids[i])
        {
            break;
        }
    }
    if (i > 0 && i == p1_neg->num_user_certificate_ids)
    {



        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Chosen end entity certificate "
                 "is not the one the peer sent us!"));
    }
}

static void
pm_ike_certs_acc_public_key_cb(
        SshEkStatus status,
        SshPublicKey public_key_return,
        void *context)
{
    struct SshPmIkeCMParam *param = context;

    if (public_key_return && (status == SSH_EK_OK))
    {
        ssh_public_key_free(param->public_key);
        param->public_key = public_key_return;
    }

    SSH_ASSERT(param->public_key != NULL);

    /* Mark that the search has succeeded */
    param->search_done = true;

    SSH_FSM_CONTINUE_AFTER_CALLBACK(param->thread);
}

static SshIkev2Error
pm_ike_certs_extract_public_key(
        struct SshPmIkeCMParam *param,
        SshCMCertificate ee_cert)
{
    SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
    SshX509Certificate x509 = NULL;
    SshPublicKey public_key = NULL;

    /* Extract the public key from ee certificate */
    if (ssh_cm_cert_get_x509(ee_cert, &x509) != SSH_CM_STATUS_OK
        || x509 == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("cmi error"));
        error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;

        pm_ike_certs_remote_error(param, "Cannot get certificate");
    }
    else
    if (ssh_x509_cert_get_public_key(x509, &public_key) == false)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Unable to get the public key from certificate"));

        error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;

        pm_ike_certs_remote_error(param, "Cannot get public key");
    }

    if (error_code == SSH_IKEV2_ERROR_OK)
    {
        param->public_key = public_key;
    }

    if (x509 != NULL)
    {
        ssh_x509_cert_free(x509);
    }

    return error_code;
}

static SshIkev2Error
pm_ike_certs_select_remote_auth_method(
        struct SshPmIkeCMParam *param,
        SshPmAuthMethod *auth_method_p)
{
    SshPublicKey public_key = param->public_key;
    SshPmAuthMethod auth_method;
    bool ok = true;

    auth_method = ssh_pm_public_key_to_auth_method(public_key);
    if (auth_method == SSH_PM_AUTH_NONE)
    {
        pm_ike_certs_remote_error(
                param,
                "Cannot resolve remote authentication method");
        ok = false;
    }

    if (ok == true)
    {
        switch (auth_method)
        {
        case SSH_PM_AUTH_RSA:
            {
                SshPm pm = param->sad_handle->pm;

                if ((pm->params.enable_key_restrictions &
                     SSH_PM_PARAM_ALGORITHMS_NIST_800_131A) != 0)
                {
                    if (ssh_public_key_select_scheme(
                                public_key,
                                SSH_PKF_SIGN,
                                "rsa-pkcs1-restricted",
                                SSH_PKF_END)
                        != SSH_CRYPTO_OK)
                    {
                        SSH_DEBUG(
                                SSH_D_FAIL,
                                ("Unable to set scheme for public key"));
                        ok = false;
                    }
                }
                else
                {
                    if (ssh_public_key_select_scheme(
                                public_key,
                                SSH_PKF_SIGN,
                                "rsa-pkcs1-implicit",
                                SSH_PKF_END)
                        != SSH_CRYPTO_OK)
                    {
                        SSH_DEBUG(
                                SSH_D_FAIL,
                                ("Unable to set scheme for public key"));
                        ok = false;
                    }
                }
            }
            break;

        case SSH_PM_AUTH_DSA:

            if (ssh_public_key_select_scheme(
                        public_key,
                        SSH_PKF_SIGN,
                        "dsa-nist-sha1",
                        SSH_PKF_END)
                != SSH_CRYPTO_OK)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Unable to set scheme for public key"));
                ok = false;
            }
            break;

#ifdef SSHDIST_CRYPT_ECP
        case SSH_PM_AUTH_ECP_DSA:
            {
                const char * scheme;
                if ((!ssh_pm_get_key_scheme(public_key, true, &scheme))
                    ||
                    (ssh_public_key_select_scheme(
                            public_key,
                            SSH_PKF_SIGN,
                            scheme,
                            SSH_PKF_END)
                     != SSH_CRYPTO_OK))
              {
                  SSH_DEBUG(
                          SSH_D_FAIL,
                          ("Unable to set scheme for public key"));
                  ok = false;
              }
            }
            break;
#endif /* SSHDIST_CRYPT_ECP */

        default:

            SSH_DEBUG(SSH_D_FAIL, ("Unsupported scheme"));
            ok = false;
            break;
        }

        if (ok == false)
        {
            pm_ike_certs_remote_error(
                    param,
                    "Cannot select remote authentication method");
        }
    }

    if (ok == true)
    {
        *auth_method_p = auth_method;
        return SSH_IKEV2_ERROR_OK;
    }
    else
    {
        return SSH_IKEV2_ERROR_CRYPTO_FAIL;
    }
}


/* Callback function for find_path operation */
static void
pm_ike_certs_public_key_find_path_cb(
        void *context,
        SshCMSearchInfo info,
        SshCMCertList list)
{
    struct SshPmIkeCMParam *param = context;
    SshPmP1 p1 = (SshPmP1) param->p1;
    SshPm pm = param->sad_handle->pm;
    SshIkev2Error error_code;
    SshCMContext cm = param->ad->cm;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Return with status %u, success %s",
             info->status,
             info->status == SSH_CM_STATUS_OK ? "Yes" : "No"));

    SSH_ASSERT(param != NULL);
    SSH_ASSERT(p1->n != NULL);

    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("PM is going down when receiving validator CB"));

        error_code = SSH_IKEV2_ERROR_GOING_DOWN;

        pm_ike_certs_remote_error(
                param,
                "Certificate validation cancelled");
        goto error;
    }

    /* Check if validator has been stoppped. */
    if (info->status == SSH_CM_STATUS_STOPPED)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Validator has been stoppped"));
        error_code = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;

        pm_ike_certs_remote_error(
                param,
                "Certificate validation cancelled");
        goto error;
    }

    /* An error occurred */
    if (info->status != SSH_CM_STATUS_OK)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Certificate path construction failed, status %d",
                 info->status));

        error_code = SSH_IKEV2_ERROR_OK;

        /* Handle error received from validator. */
        pm_ike_certs_remote_validator_error(param, info);

        goto error;
    }

    if (ssh_cm_cert_list_empty(list))
    {
        /* Empty list */
        SSH_DEBUG(SSH_D_FAIL, ("No suitable certificate path found"));
        error_code = SSH_IKEV2_ERROR_OK;

        pm_ike_certs_remote_error(
                param,
                "Certificate path not found");
        goto error;
    }

    /* Store CA and end entity certificate to IKE SA. */
    pm_ike_sa_store_certificates(p1, list);

    /* Extract public key. */
    error_code = pm_ike_certs_extract_public_key(param, p1->auth_cert);
    if (error_code != SSH_IKEV2_ERROR_OK)
    {
        goto error;
    }

    /* Select remote authentication method. */
    error_code =
        pm_ike_certs_select_remote_auth_method(param, &p1->remote_auth_method);
    if (error_code != SSH_IKEV2_ERROR_OK)
    {
        goto error;
    }

    /* List not needed anymore, free it. */
    ssh_cm_cert_list_free(cm, list);

    /* Try to accelerate the public key if possible */
    if (pm->accel_short_name)
    {
        ssh_ek_generate_accelerated_public_key(
                pm->externalkey,
                pm->accel_short_name,
                param->public_key,
                pm_ike_certs_acc_public_key_cb,
                param);
    }
    else
    {
        /* Cannot use acceleration */
        pm_ike_certs_acc_public_key_cb(SSH_EK_OK, NULL, param);
    }

    return;

   error:
    if (cm != NULL)
    {
        ssh_cm_cert_list_free(cm, list);
    }

    if (param->public_key != NULL)
    {
        ssh_public_key_free(param->public_key);
        param->public_key = NULL;
    }

    ssh_pm_ike_sa_release_certificates(p1);

    /* Store error code. */
    param->error_code = error_code;

    SSH_FSM_CONTINUE_AFTER_CALLBACK(param->thread);
}

static void
pm_ike_certs_pubkey_find_aborted(
        void *context)
{
    struct SshPmIkeCMParam *param = context;

    param->p1->callbacks.u.public_key_cb = NULL_FNPTR;
    /* Can not abort CM right now... It will complete and release its
       reference to P1 eventually. Mark operation aborted. */
    param->p1->callbacks.aborted = true;
}

static void
pm_st_ike_get_public_key_destructor(
        SshFSM fsm,
        void *context)
{
    struct SshPmIkeCMParam *param = context;

    pm_ike_certs_param_free(param);
}

static SshIkev2Error
pm_ike_certs_set_ee_constraints(
        struct SshPmIkeCMParam *param,
        SshCMSearchConstraints *ee_constraints_p)
{
    SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
    SshCMSearchConstraints ee_constraints;
    SshCertDBKey *ee_keys = NULL;
    SshPmP1 p1 = param->p1;
    SshPmP1Negotiation p1_neg = p1->n;
    int i;

    /* Set up search constraints for remote end certificate */
    ee_constraints = ssh_cm_search_allocate();
    if (ee_constraints == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate search constraints"));

        pm_ike_certs_remote_error(
                param,
                "Cannot allocate memory");

        error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

    /* Get remote identity */
    if (error_code == SSH_IKEV2_ERROR_OK)
    {
        SshIkev2PayloadID payload_id;

        payload_id = param->ee_key;
        SSH_ASSERT(payload_id != NULL);
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Remote identity %@",
                 ssh_pm_ike_id_render, payload_id));

        switch (payload_id->id_type)
        {
        case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
        case SSH_IKEV2_ID_TYPE_IPV6_ADDR:

            if (ssh_cm_key_set_ip(
                        &ee_keys,
                        payload_id->id_data,
                        payload_id->id_data_size)
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set IP address"));

                pm_ike_certs_remote_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }

            break;

        case SSH_IKEV2_ID_TYPE_RFC822_ADDR:

            if (ssh_cm_key_set_email(
                        &ee_keys,
                        (const char *) payload_id->id_data,
                        payload_id->id_data_size)
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set email"));

                pm_ike_certs_remote_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }

            break;

        case SSH_IKEV2_ID_TYPE_FQDN:

            if (ssh_cm_key_set_dns(
                        &ee_keys,
                        (const char *) payload_id->id_data,
                        payload_id->id_data_size)
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set DNS"));

                pm_ike_certs_remote_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }

            break;

        case SSH_IKEV2_ID_TYPE_ASN1_DN:

            if (ssh_cm_key_set_dn(
                        &ee_keys,
                        payload_id->id_data,
                        payload_id->id_data_size)
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set DN"));

                pm_ike_certs_remote_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }

            break;

        case SSH_IKEV2_ID_TYPE_KEY_ID:

            if (ssh_cm_key_set_x509_key_identifier(
                        &ee_keys,
                        payload_id->id_data,
                        payload_id->id_data_size)
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set x509 key identifier"));

                pm_ike_certs_remote_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }

            break;

        case SSH_IKEV2_ID_TYPE_ASN1_GN:
        default:

            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Unknown payload id type %d",
                     payload_id->id_type));

            pm_ike_certs_remote_error(
                    param,
                    "Unknown payload id type");

            error_code = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
            break;
        }
    }

    if (error_code == SSH_IKEV2_ERROR_OK)
    {
        /* Add cache id of the certificate the peer has sent us. Note
           that the search is performed first with all known cache ids
           and finally without the cache id constraint if no matches
           are found. */
        if (param->ignore_user_cache_id == false)
        {
            SSH_ASSERT(param->user_index < p1_neg->num_user_certificate_ids);

            if (ssh_cm_key_set_cache_id(
                        &ee_keys,
                        p1_neg->user_certificate_ids[param->user_index])
                == false)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not set cache id"));

                pm_ike_certs_remote_error(param, "Cannot allocate memory");

                error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }
        }
    }

    if (error_code == SSH_IKEV2_ERROR_OK)
    {
        SshBerTimeStruct start_time;
        SshBerTimeStruct end_time;
        SshTime now;

        ssh_cm_search_set_keys(ee_constraints, ee_keys);

        /* Add certificate/Crl access hints received from the peer with
           hash-and-url of cert. */
        for (i = 0; i < p1_neg->num_cert_access_urls; i++)
        {
            ssh_cm_search_add_access_hints(
                    ee_constraints,
                    p1_neg->cert_access_urls[i]);
        }

        /* Require end entity certificate to be valid now and in the near
           future */

        now = ssh_time();
        ssh_ber_time_set_from_unix_time(&start_time, now);
        ssh_ber_time_set_from_unix_time(&end_time, now + 120);
        ssh_cm_search_set_time(ee_constraints, &start_time, &end_time);

#ifdef SSHDIST_IKEV1
        ssh_cm_search_set_key_type(ee_constraints, param->key_type);
#endif /* SSHDIST_IKEV1 */
    }

    if (error_code != SSH_IKEV2_ERROR_OK)
    {
        if (ee_constraints != NULL)
        {
            ssh_cm_search_free(ee_constraints);
            ee_constraints = NULL;
        }
    }

    *ee_constraints_p = ee_constraints;

    return error_code;
}

static SshIkev2Error
pm_ike_certs_set_ca_constraints(
        struct SshPmIkeCMParam *param,
        SshCMSearchConstraints *ca_constraints_p)
{
    SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
    SshCMSearchConstraints ca_constraints;
    SshCertDBKey *ca_keys = NULL;
    SshPmCa ca;

    /* Set up search constraints for ca certificate */
    ca_constraints = ssh_cm_search_allocate();
    if (ca_constraints == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate search constraints"));

        pm_ike_certs_remote_error(param, "Cannot allocate memory");

        error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }
    else
    {
        SshPmAuthDomain ad = param->ad;

        SSH_ASSERT(param->ca_index < ad->num_cas);
        ca = ad->cas[param->ca_index];

        if (ssh_cm_key_set_x509_key_identifier(
                    &ca_keys,
                    ca->cert_key_id,
                    ca->cert_key_id_len)
            == false)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Could not set x509 key identifier"));

            pm_ike_certs_remote_error(param, "Cannot allocate memory");

            error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
        else
        {
            ssh_cm_search_set_keys(ca_constraints, ca_keys);
        }
    }

    if (error_code != SSH_IKEV2_ERROR_OK)
    {
        if (ca_constraints != NULL)
        {
            ssh_cm_search_free(ca_constraints);
            ca_constraints = NULL;
        }
    }

    *ca_constraints_p = ca_constraints;

    return error_code;
}

static SshIkev2Error
pm_ike_certs_set_search_constraints(
        struct SshPmIkeCMParam *param,
        SshCMSearchConstraints *ee_constraints_p,
        SshCMSearchConstraints *ca_constraints_p)
{
    SshIkev2Error error_code;

    *ee_constraints_p = NULL;
    *ca_constraints_p = NULL;

    error_code = pm_ike_certs_set_ee_constraints(param, ee_constraints_p);
    if (error_code == SSH_IKEV2_ERROR_OK)
    {
        error_code = pm_ike_certs_set_ca_constraints(param, ca_constraints_p);
        if (error_code != SSH_IKEV2_ERROR_OK)
        {
            ssh_cm_search_free(*ee_constraints_p);
            *ee_constraints_p = NULL;
        }
    }

    return error_code;
}


SSH_FSM_STEP(pm_st_ike_get_public_key_find_path);
SSH_FSM_STEP(pm_st_ike_get_public_key_failed);
SSH_FSM_STEP(pm_st_ike_get_public_key_finish);

SSH_FSM_STEP(pm_st_ike_get_public_key_find_path)
{
    struct SshPmIkeCMParam *param = thread_context;
    SshCMSearchConstraints ee_constraints = NULL;
    SshCMSearchConstraints ca_constraints = NULL;
    SshIkev2Error error_code;
    bool success = false;
    SshCMContext cm = param->ad->cm;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Entering public key find path %d",
             param->ca_index));

    /* Check for errors from the pm_ike_get_certificates_find_path_cb
       callback. */
    if (param->error_code != SSH_IKEV2_ERROR_OK)
    {
        goto out;
    }

    /* Is the search operation completed successfully? */
    if (param->search_done)
    {
        pm_ike_certs_remote_validation_done(param);

        success = true;
        goto out;
    }

    /* Check if validation process should go to next round. */
    if (pm_ike_certs_remote_validation_continue(param) == false)
    {
        param->error_code = SSH_IKEV2_ERROR_OK;
        goto out;
    }

    /* Set search constraints for the validator. */
    error_code =
        pm_ike_certs_set_search_constraints(
                param,
                &ee_constraints,
                &ca_constraints);

    if (error_code != SSH_IKEV2_ERROR_OK)
    {
        SSH_ASSERT(ee_constraints == NULL);
        SSH_ASSERT(ca_constraints == NULL);

        param->error_code = error_code;
        goto out;
    }

    SSH_FSM_ASYNC_CALL({
            ssh_cm_find_path(
                    cm,
                    ca_constraints,
                    ee_constraints,
                    pm_ike_certs_public_key_find_path_cb,
                    param);
        });
    SSH_NOTREACHED;

    /* Error handling. */

   out:

    if (success == true)
    {
        SSH_FSM_SET_NEXT(pm_st_ike_get_public_key_finish);
    }
    else
    {
        SSH_FSM_SET_NEXT(pm_st_ike_get_public_key_failed);
    }

    return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(pm_st_ike_get_public_key_failed)
{
    struct SshPmIkeCMParam *param = thread_context;
    SshPmP1 p1 = param->p1;

    /* Inform the IKE library that public key lookup did not succeed. */
    if (!p1->callbacks.aborted)
    {
        if (p1->callbacks.u.public_key_cb)
        {
            (*p1->callbacks.u.public_key_cb)(
                    param->error_code,
                    NULL,
                    p1->callbacks.callback_context);
        }

        ssh_operation_unregister_no_free(p1->callbacks.operation);
    }

    pm_ike_certs_remote_validation_complete(false);

    return SSH_FSM_FINISH;
}

SSH_FSM_STEP(pm_st_ike_get_public_key_finish)
{
    struct SshPmIkeCMParam *param = thread_context;
    SshPmP1 p1 = param->p1;

    /* Return the public key to the IKE library. */
    if (!p1->callbacks.aborted)
    {
        if (p1->callbacks.u.public_key_cb)
        {
            (*p1->callbacks.u.public_key_cb)(
                    SSH_IKEV2_ERROR_OK,
                    param->public_key,
                    p1->callbacks.callback_context);
        }

        ssh_operation_unregister_no_free(p1->callbacks.operation);
    }
    ssh_public_key_free(param->public_key);

    pm_ike_certs_remote_validation_complete(true);

    return SSH_FSM_FINISH;
}


SshOperationHandle
ssh_pm_ike_public_key(
        SshSADHandle sad_handle,
        SshIkev2ExchangeData ed,
        SshIkev2PadPublicKeyCB reply_callback,
        void *reply_callback_context)
{
    SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
    struct SshPmIkeCMParam *param = NULL;
    SshPmP1Negotiation p1_neg;
    SshIkev2PayloadID payload_id;
    SshPm pm = sad_handle->pm;
    SshPmAuthDomain ad = NULL;
    SshPmP1 p1;

    SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

    p1 = (SshPmP1)ed->ike_sa;

    SSH_PM_ASSERT_P1(p1);

    /* If policymanager is not in active state, we wan't to reject this. */
    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
        error_code = SSH_IKEV2_ERROR_SUSPENDED;
        goto error;
    }

    /* Fail request if not in IKE SA negotiation phase. */
    p1_neg = p1->n;
    if (p1_neg == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Failing public key request received outside IKE "
                 "negotiation"));
        error_code = SSH_IKEV2_ERROR_SA_UNUSABLE;
        goto error;
    }

    /* Select a tunnel for the reponder if not already done */
    if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
        error_code = ssh_pm_select_ike_responder_tunnel(pm, p1, ed);
        if (error_code != SSH_IKEV2_ERROR_OK)
        {
            error_code = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
            goto error;
        }
    }

    /* If the IKE initiator has used the "me Tarzan, you Jane" option,
       then check here that that responder has replied with an
       acceptable identity. */
    if (!ssh_pm_ike_check_requested_identity(
                sad_handle->pm,
                p1,
                ed->ike_ed->id_r))
    {
        error_code = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
        p1_neg->failure_mask |= SSH_PM_E_REMOTE_ID_MISMATCH;
        goto error;
    }

    /* Verify correct authentication domain */
    if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    {
        goto error;
    }
    else
    {
        ad = p1->auth_domain;
    }

    /* Are we using certs? */
    if (ad->num_cas == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Authentication domain has no CAs set"));
        p1_neg->failure_mask |= SSH_PM_E_AUTH_METHOD_MISMATCH;
        goto error;
    }

    /* Resolve payload id. */
    if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
        payload_id = ssh_pm_ikev2_payload_id_dup(ed->ike_ed->id_r);
    }
    else
    {
        payload_id = ssh_pm_ikev2_payload_id_dup(ed->ike_ed->id_i);
    }

    if (payload_id == NULL)
    {
        goto error;
    }

    /* Allocate context for callback */
    param =
        pm_ike_certs_param_alloc(
                sad_handle,
                p1,
                ad,
                pm_ike_certs_get_key_type(ed),
                payload_id);

    if (param == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate callback context"));
        error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    /* Prepare for remote end certificate lookup. */

    param->create_path = true;

    pm_ike_certs_remote_validation_start(param);

    ssh_fsm_thread_init(
            &pm->fsm,
            &p1_neg->sub_thread,
            pm_st_ike_get_public_key_find_path,
            NULL_FNPTR,
            pm_st_ike_get_public_key_destructor,
            param);

    ssh_fsm_set_thread_name(&p1_neg->sub_thread, "IKE find public key");
    param->thread = &p1_neg->sub_thread;

    ssh_operation_register_no_alloc(
            p1->callbacks.operation,
            pm_ike_certs_pubkey_find_aborted,
            param);

    p1->callbacks.aborted = false;
    p1->callbacks.u.public_key_cb = reply_callback;
    p1->callbacks.callback_context = reply_callback_context;

    return p1->callbacks.operation;

   error:

    (*reply_callback)(error_code, NULL, reply_callback_context);
    return NULL;
}

/***************************** New Certificate Request ***********************/

void
ssh_pm_ike_new_certificate_request(
        SshSADHandle sad_handle,
        SshIkev2ExchangeData ed,
        SshIkev2CertEncoding ca_encoding,
        const unsigned char *certificate_authority,
        size_t certificate_authority_len)
{
    SshPm pm = sad_handle->pm;
    SshPmP1 p1 = (SshPmP1) ed->ike_sa;
    SshPmP1Negotiation p1_neg = p1->n;
    const unsigned char *ca;
    unsigned char **cas = NULL;
    size_t *ca_lens = NULL;
    int num_cas;
    size_t real_len;
    int i;

    SSH_DEBUG(
            SSH_D_MIDSTART,
            ("New certificate request: encoding=%s(%d)",
             ssh_ikev2_cert_encoding_to_string(ca_encoding),
             ca_encoding));

    if (certificate_authority == NULL || certificate_authority_len == 0)
    {
        SSH_DEBUG(
                SSH_D_UNCOMMON,
                ("Invalid certificate request: length %d",
                 (int) certificate_authority_len));
        return;
    }

    SSH_DEBUG_HEXDUMP(
            SSH_D_PCKDMP,
            ("Certificate request:"),
            certificate_authority,
            certificate_authority_len);

    /* If policymanager is not in active state, we wan't to reject this. */
    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED ||
        ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
        return;
    }

    /* Ignore request if not in IKE SA negotiation phase. */
    if (p1_neg == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Ignoring new certificate request received outside IKE "
                 "negotiation"));
        return;
    }

    /* Verify correct authentication domain */
    if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    {
        return;
    }

    /* Just a minor sanity checking. */
    switch (ca_encoding)
    {
    case SSH_IKEV2_CERT_X_509:
        break;

    default:
        SSH_DEBUG(SSH_D_FAIL, ("Unsupported CA encoding %d", ca_encoding));
        return;
        break;
    }

#ifdef SSHDIST_IKEV1
    if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
        num_cas = 1;

        SSH_DEBUG(SSH_D_NICETOKNOW, ("Received CA for IKEv1"));

        real_len = certificate_authority_len;
        ca = certificate_authority;
    }
    else
#endif /* SSHDIST_IKEV1 */
    {
        ca = certificate_authority;

        if ((certificate_authority_len % 20) != 0)
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Invalid CA public key hash length %d",
                     certificate_authority_len));
            return;
        }

        real_len = 20;
        num_cas = certificate_authority_len / real_len;
    }

    cas =
        ssh_realloc(
                p1_neg->crs.cas,
                (p1_neg->crs.num_cas * sizeof(*p1_neg->crs.cas)),
                (p1_neg->crs.num_cas + num_cas) * sizeof(*p1_neg->crs.cas));
    ca_lens =
        ssh_realloc(
                p1_neg->crs.ca_lens,
                (p1_neg->crs.num_cas * sizeof(*p1_neg->crs.ca_lens)),
                (p1_neg->crs.num_cas + num_cas) *
                sizeof(*p1_neg->crs.ca_lens));

    if (cas == NULL || ca_lens == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not add new certificate request"));
        /* Sorry, we must free also the old ones since the ssh_realloc()
           API requires us to know the old length and now some of our
           arrays might use the old length and some the new length. */

        goto error;
    }

    /* Add new certificate request. */
    for (i = 0; i < num_cas; i++)
    {
        cas[p1_neg->crs.num_cas + i] =
            ssh_memdup(ca + (i * real_len), real_len);

        if (cas[p1_neg->crs.num_cas + i] == NULL)
        {
            goto error;
        }

        ca_lens[p1_neg->crs.num_cas + i] = real_len;
    }

    p1_neg->crs.cas = cas;
    p1_neg->crs.ca_lens = ca_lens;
    p1_neg->crs.num_cas += num_cas;
    return;

   error:
    if (cas)
    {
        ssh_free(cas);
    }

    if (ca_lens)
    {
        ssh_free(ca_lens);
    }

    if (p1_neg != NULL)
    {
        if (p1_neg->crs.cas)
        {
            for (i = 0; i < p1_neg->crs.num_cas; i++)
            {
                ssh_free(p1_neg->crs.cas[i]);
            }
        }

        ssh_free(p1_neg->crs.cas);
        ssh_free(p1_neg->crs.ca_lens);
        memset(&p1_neg->crs, 0, sizeof(p1_neg->crs));
    }
}

/***************************** New Certificate *******************************/

void
ssh_pm_ike_new_certificate(
        SshSADHandle sad_handle,
        SshIkev2ExchangeData ed,
        SshIkev2CertEncoding cert_encoding,
        const unsigned char *cert_data,
        size_t cert_data_len)
{
    SshPm pm = sad_handle->pm;
    SshPmP1 p1 = (SshPmP1) ed->ike_sa;
    SshPmP1Negotiation p1_neg = p1->n;

    SSH_DEBUG(
            SSH_D_MIDSTART,
            ("New certificate: encoding=%s(%d)",
             ssh_ikev2_cert_encoding_to_string(cert_encoding),
             cert_encoding));

    if (cert_data == NULL || cert_data_len == 0)
    {
        SSH_DEBUG(
                SSH_D_UNCOMMON,
                ("Invalid certificate: length %d",
                 (int) cert_data_len));
        return;
    }

    SSH_DEBUG_HEXDUMP(
            SSH_D_PCKDMP,
            ("Certificate:"),
            cert_data,
            cert_data_len);






    if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("PM is going down, failing certificate install"));
        return;
    }

    /* Ignore certificate if not in IKE SA negotiation phase. */
    if (p1_neg == NULL)
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Ignoring new certificate received "
                 "outside IKE negotiation"));
        return;
    }

    /* Verify correct authentication domain */
    if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    {
        SSH_DEBUG(SSH_D_FAIL, ("Unable to get authentication domain, failed "
                               "to install certificate."));
        return;
    }

    switch (cert_encoding)
    {
    case SSH_IKEV2_CERT_ARL:
    case SSH_IKEV2_CERT_CRL:

        /* Add the CRL to the Certificate Manager. */
        if (!ssh_pm_cm_new_crl(
                    p1->auth_domain->cm,
                    cert_data,
                    cert_data_len,
                    true))
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("Could not add CRL into certificate manager"));
        }
        break;

    case SSH_IKEV2_CERT_PKCS7_WRAPPED_X_509:
        {
            SshCMStatus ret;

            ret =
                ssh_cm_add_pkcs7_ber(
                        p1->auth_domain->cm,
                        (unsigned char*)cert_data,
                        cert_data_len);
            if (ret != SSH_CM_STATUS_ALREADY_EXISTS)
            {
                SSH_DEBUG(SSH_D_FAIL, ("ssh_cm_add failed: %d", ret));
            }
        }
        break;

    case SSH_IKEV2_CERT_X_509:
        {
            SshX509Certificate x509 = NULL;
            SshCMCertificate cert;
            size_t pathlength = 0;
            bool is_ca;
            bool critical;

            /* Add certificate to cache */
            SSH_ASSERT(p1->auth_domain != NULL);
            cert =
                ssh_pm_auth_domain_add_cert_internal(
                        sad_handle->pm,
                        p1->auth_domain,
                        cert_data,
                        cert_data_len,
                        true);
            if (cert == NULL)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Unable to add certificate to cache"));

                return;
            }
            SSH_ASSERT(cert != NULL);

            /* Classify certificate and store certificate id */
            is_ca = false;
            if (ssh_cm_cert_get_x509(cert, &x509) != SSH_CM_STATUS_OK)
            {
                SSH_DEBUG(SSH_D_FAIL, ("Could not get x509 certificate"));
                return;
            }

            ssh_x509_cert_get_basic_constraints(
                    x509,
                    &pathlength,
                    &is_ca,
                    &critical);
            if (is_ca)
            {
                uint8_t count = p1_neg->num_ca_certificate_ids;

                if (count < SSH_PM_P1N_NUM_CA_CERT_IDS)
                {
                    p1_neg->ca_certificate_ids[count] =
                        ssh_cm_cert_get_cache_id(cert);
                    p1_neg->num_ca_certificate_ids++;
                }
            }
            else
            {
                uint8_t count = p1_neg->num_user_certificate_ids;

                if (count < SSH_PM_P1N_NUM_USER_CERT_IDS)
                {
                    p1_neg->user_certificate_ids[count] =
                        ssh_cm_cert_get_cache_id(cert);
                    p1_neg->num_user_certificate_ids++;
                }
          }
            ssh_x509_cert_free(x509);
        }
        break;

    case SSH_IKEV2_CERT_HASH_AND_URL_X509:
    case SSH_IKEV2_CERT_HASH_AND_URL_X509_BUNDLE:
        /* Bundle identifier is stored into negotiation to be used
           later, when the search is made. */
        if (cert_data_len > 28) /* 20 + 'http://x/' */
        {
            void *tmp;

            tmp =
                ssh_realloc(
                        p1_neg->cert_access_urls,
                        p1_neg->num_cert_access_urls * sizeof(char *),
                        (1 + p1_neg->num_cert_access_urls) * sizeof(char *));
            if (tmp != NULL)
            {
                p1_neg->cert_access_urls = tmp;
                p1_neg->cert_access_urls[p1_neg->num_cert_access_urls] =
                    ssh_memdup(cert_data + 20, cert_data_len - 20);

                if (p1_neg->cert_access_urls[p1_neg->num_cert_access_urls]
                    != NULL)
                {
                    p1_neg->num_cert_access_urls += 1;
                }
            }
        }
        break;

    case SSH_IKEV2_CERT_RAW_RSA_KEY:
    default:
        SSH_DEBUG(
                SSH_D_NICETOKNOW,
                ("Unsupported certificate encoding `%s' (%d)",
                 ssh_ikev2_cert_encoding_to_string(cert_encoding),
                 cert_encoding));
        break;

    }
}
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
