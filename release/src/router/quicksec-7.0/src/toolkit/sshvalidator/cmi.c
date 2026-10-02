/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of the SSH Certificate Validator (former Certificate
   Manager, thus still called SSH CMi).
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "cmi.h"
#include "cmi-internal.h"
#include "sshadt.h"
#include "sshadt_map.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertCMi"



const SshKeywordStruct ssh_cm_error_strs[] =
{
    { "Success",
      SSH_CM_OK},
    { "Signature algorithm or key size too insecure",
      SSH_CM_ERROR_ALGORITHM_STRENGTH_TOO_WEAK },
    { "Communication with external server failed",
      SSH_CM_ERROR_EDB_METHOD_FAILED },
    { "Connection to external server failed",
      SSH_CM_ERROR_EDB_METHOD_DISCONNECTED },
    { "Connection to external server timed out",
      SSH_CM_ERROR_EDB_METHOD_TIMEOUT },
    { "Public key of certificate does not match search constraint",
      SSH_CM_ERROR_CERT_ALGORITHM_MISMATCH },
    { "Certificate signature algorithm or key size too insecure",
      SSH_CM_ERROR_CERT_ALGORITHM_STRENGTH_TOO_WEAK },
    { "Invalid CA certificate",
      SSH_CM_ERROR_CERT_CA_INVALID },
    { "Certificate path construction did not succeed",
      SSH_CM_ERROR_CERT_CHAIN_LOOP },
    { "Certificate contains an unsupported critical extension",
      SSH_CM_ERROR_CERT_UNSUPPORTED_CRITICAL_EXT },
    { "Certificate decoding failed",
      SSH_CM_ERROR_CERT_DECODE_FAILED },
    { "Invalid certificate encountered",
      SSH_CM_ERROR_CERT_INVALID },
    { "Certificate signature verification failed",
      SSH_CM_ERROR_CERT_INVALID_SIGNATURE },
    { "Certificate key usage does not match search constraint",
      SSH_CM_ERROR_CERT_KEY_USAGE_MISMATCH },
    { "Certificate was not found",
      SSH_CM_ERROR_CERT_NOT_FOUND },
    { "Certificate is not valid at this time",
      SSH_CM_ERROR_CERT_NOT_IN_INTERVAL },
    { "Certificate has been revoked",
      SSH_CM_ERROR_CERT_REVOKED },
    { "Certificate has been suspended",
      SSH_CM_ERROR_CERT_SUSPENDED },
    { "Certificate validity period could not be determined",
      SSH_CM_ERROR_CERT_VALIDITY_PERIOD_NOT_DETERMINED },
    { "CRL signature algorithm or key size too insecure",
      SSH_CM_ERROR_CRL_ALGORITHM_STRENGTH_TOO_WEAK },
    { "CRL decoding failed",
      SSH_CM_ERROR_CRL_DECODE_FAILED },
    { "Revocation status could not be checked because CRL is invalid",
      SSH_CM_ERROR_CRL_INVALID },
    { "Revocation status could not be checked because CRL signature "
      "verification failed",
      SSH_CM_ERROR_CRL_INVALID_SIGNATURE },
    { "Revocation status could not be checked because CRL was not found",
      SSH_CM_ERROR_CRL_NOT_FOUND },
    { "Revocation status could not be checked because CRL had expired",
      SSH_CM_ERROR_CRL_OLD },
    { "Revocation status could not be checked with OCSP, and CRL is not "
      "available",
      SSH_CM_ERROR_REVOCATION_CHECK_FAILED_FROM_OCSP_AND_CRL },
    { "Out of resources",
      SSH_CM_ERROR_INSUFFICIENT_RESOURCES },
    { "Certificate contains an impossible validity period",
      SSH_CM_ERROR_INTERVAL_NOT_VALID },
    { "Invalid policy",
      SSH_CM_ERROR_INVALID_POLICY },
    { "Out of memory",
      SSH_CM_ERROR_MEMORY_ALLOC_FAILED },
    { "Maximum certificate chain length reached",
      SSH_CM_ERROR_PATH_LENGTH_REACHED },
    { "Certificate chain could not be verified",
      SSH_CM_ERROR_PATH_NOT_VERIFIED },
    { "Date and time information not available",
      SSH_CM_ERROR_TIMES_UNAVAILABLE },
    { "Undefined error",
      SSH_CM_ERROR_UNDEFINED },
    { NULL },
};


/* Subject has failed in conjunction with the issuer. */
static void
cm_failure_list_add(SshCMSearchContext *search,
                    unsigned int issuer_id, unsigned int subject_id)
{
    SshCMSearchSignatureFailure tmp;

    tmp = ssh_realloc(search->failure_list,
                      search->failure_list_size * sizeof(*tmp),
                      (1 + search->failure_list_size) * sizeof(*tmp));
    if (tmp != NULL)
    {
        tmp[search->failure_list_size].issuer_id = issuer_id;
        tmp[search->failure_list_size].subject_id = subject_id;
        search->failure_list = tmp;
        search->failure_list_size += 1;
    }
}

static bool
cm_failure_list_member(SshCMSearchContext *search,
                       unsigned int issuer_id, unsigned int subject_id)
{
    int i;
    SshCMSearchSignatureFailure fentry;

    for (i = 0; i < search->failure_list_size; i++)
    {
        fentry = &search->failure_list[i];
        if (fentry->issuer_id == issuer_id &&
            fentry->subject_id == subject_id)
        {
            return true;
        }
    }
    return false;
}

/* Canonize DER */
unsigned char *
cm_canon_der(const unsigned char *der, size_t der_len, size_t *canon_der_len)
{
    unsigned char *canon_der;
    SshDNStruct dn;

    *canon_der_len = 0;

    ssh_dn_init(&dn);
    if (ssh_dn_decode_der(der, der_len, &dn, NULL) == 0)
    {
        ssh_dn_clear(&dn);
        return NULL;
    }

    if (ssh_dn_encode_der_canonical(&dn, &canon_der, canon_der_len, NULL) == 0)
    {
        ssh_dn_clear(&dn);
        return NULL;
    }

    ssh_dn_clear(&dn);
    return canon_der;
}

/* True iff canonical der's of n1 and n2 match */
bool
cm_name_equal(SshX509Name n1, SshX509Name n2)
{

    bool rv;
    unsigned char *d1, *d2;
    size_t d1_len, d2_len;

    if (n1 != NULL && n1->canon_der == NULL)
    {
        ssh_x509_name_reset(n1);
        if (!ssh_x509_name_pop_der_dn(n1, &d1, &d1_len))
          return false;
        n1->canon_der = cm_canon_der(d1, d1_len, &n1->canon_der_len);
        ssh_free(d1);
    }

    if (n2 != NULL && n2->canon_der == NULL)
    {
        ssh_x509_name_reset(n2);
        if (!ssh_x509_name_pop_der_dn(n2, &d2, &d2_len))
        {
            ssh_free(d2);
            return false;
        }

        n2->canon_der = cm_canon_der(d2, d2_len, &n2->canon_der_len);
        ssh_free(d2);
    }

    if (n1 == NULL || n2 == NULL)
      return false;

    if (n1->canon_der_len != n2->canon_der_len)
      rv = false;
    else
      rv = !memcmp(n1->canon_der, n2->canon_der, n1->canon_der_len);

    return rv;
}


/* Return true, if issuer is really issuer of the subject, e.g. the
   issuer canonical name matches subject's issuer canonical name. We
   need to check these, as we might have encountered wrong cert via
   issuer/subject key identifier mapping. */
bool
cm_verify_issuer_name(SshCMCertificate subject, SshCMCertificate issuer)
{
    return cm_name_equal(subject->cert->issuer_name,
                         issuer->cert->subject_name);
}

bool
cm_verify_issuer_id(SshCMCertificate subject, SshCMCertificate issuer)
{
    bool rv;
    SshX509ExtKeyId s_ikid;
    bool critical;

    if (!ssh_x509_cert_get_authority_key_id(subject->cert,
                                            &s_ikid, &critical))
    {
        /* Subject does not specify issuer kid, we assume it's OK, as
           issuer was originally found by name */
        return true;
    }

    if (s_ikid->key_id_len)
    {
        unsigned char *i_skid;
        size_t i_skid_len;

        if (ssh_x509_cert_get_subject_key_id(issuer->cert,
                                             &i_skid, &i_skid_len,
                                             &critical))
        {
            if (i_skid_len == s_ikid->key_id_len &&
                memcmp(i_skid, s_ikid->key_id, i_skid_len) == 0)
            {
                /* Key ID matches */
                return true;
            }
            else
            {
                /* subject's issuer key id does not match issuer
                   candidates subject key id. */
                return false;
            }
        }
        /* subject had issuer binary issuer kid, but the issuer did not
           have subject key id, assume its OK. */
        return true;
    }

    if (s_ikid->auth_cert_issuer)
    {
        SshMPIntegerStruct serial;

        ssh_mprz_init(&serial);
        ssh_x509_cert_get_serial_number(issuer->cert, &serial);
        if (ssh_mprz_cmp(&s_ikid->auth_cert_serial_number, &serial) != 0)
        {
            ssh_mprz_clear(&serial);
            return false;
        }
        ssh_mprz_clear(&serial);

        rv = cm_name_equal(s_ikid->auth_cert_issuer,
                           issuer->cert->subject_name);
        ssh_x509_name_reset(s_ikid->auth_cert_issuer);
        ssh_x509_name_reset(issuer->cert->subject_name);

        return rv;
    }

    return true;
}

/* Search terminated, call the callback */
static void
cm_search_callback(SshCMSearchContext *search,
                   int status,
                   SshCertDBEntryList *result)
{
    struct SshCMSearchInfoRec info = { 0 };

    info.status = status;
    info.state = search->state;
    info.error = search->error;
    info.error_string = search->error_string;
    info.error_string_len = search->error_string_len;

    SSH_ASSERT(search->terminated == false);

    search->cm->in_callback++;
    (*search->callback)(search->search_context, &info, result);
    search->cm->in_callback--;
}

/* A routine that is called by the certificate cache when data needs
   to be freed. */
static void ssh_cm_data_free(unsigned int tag, void *context)
{
    SSH_DEBUG(SSH_D_HIGHSTART, ("Data free called by database."));

    /* Ignore NULL contexts. */
    if (context == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("*** For some reason data was NULL."));
        return;
    }

    switch (tag)
    {
      case SSH_CM_DATA_TYPE_CERTIFICATE:
      {
          SshCMCertificate cm_cert = context;

          cm_cert->entry = NULL;
          ssh_cm_cert_free(cm_cert);
          break;
      }
      case SSH_CM_DATA_TYPE_CRL:
      {
          SshCMCrl cm_crl = context;

          cm_crl->entry = NULL;
          ssh_cm_crl_free(cm_crl);
          break;
      }
      default:
        /* Failure not supported. */
        return;
    }
}

/************ CM Search constraints  *************/

SshCMSearchConstraints ssh_cm_search_allocate(void)
{
    SshCMSearchConstraints constraints = ssh_calloc(1, sizeof(*constraints));

    SSH_DEBUG(SSH_D_MIDSTART, ("Allocate search constraints."));

    if (constraints)
    {
        constraints->keys        = NULL;
        constraints->issuer_keys = NULL;
        ssh_ber_time_zero(&constraints->not_before);
        ssh_ber_time_zero(&constraints->not_after);
        constraints->max_path_length = (size_t)-1;
        constraints->key_usage_flags = 0;
        constraints->pk_algorithm = SSH_X509_PKALG_UNKNOWN;
        constraints->rule         = SSH_CM_SEARCH_RULE_AND;
        constraints->group        = false;
        constraints->upto_root    = false;

        constraints->local.crl    = false;
        constraints->local.cert   = false;

#ifdef SSHDIST_VALIDATOR_OCSP
        constraints->ocsp_mode = SSH_CM_OCSP_CRL_AFTER_OCSP;
#endif /* SSHDIST_VALIDATOR_OCSP */

        ssh_mprz_init(&constraints->trusted_roots.trusted_set);
        ssh_ber_time_zero(&constraints->trusted_roots.trusted_not_after);

        constraints->check_revocation = true;

        constraints->inhibit_policy_mapping = 0;
        constraints->inhibit_any_policy = 0;
        constraints->policy_mapping = 0;

        constraints->user_initial_policy_set = NULL;
        constraints->user_initial_policy_set_size = 0;
    }

    SSH_DEBUG(SSH_D_MIDSTART, ("Returning constraints (%p)", constraints));

    return constraints;
}

void ssh_cm_search_free(SshCMSearchConstraints constraints)
{
    int i;

    SSH_DEBUG(SSH_D_MIDSTART, ("Free search constraints (%p).", constraints));

    /* Clean the search constraints. */
    ssh_certdb_key_free(constraints->keys);
    ssh_mprz_clear(&constraints->trusted_roots.trusted_set);

    for (i = 0; i < constraints->user_initial_policy_set_size; i++)
      ssh_free(constraints->user_initial_policy_set[i]);
    ssh_free(constraints->user_initial_policy_set);

    for (i = 0; i < constraints->num_access; i++)
      ssh_free(constraints->access[i].url);
    ssh_free(constraints->access);

    ssh_free(constraints);
}

void ssh_cm_search_set_policy(SshCMSearchConstraints constraints,
                              uint32_t explicit_policy,
                              uint32_t inhibit_policy_mappings,
                              uint32_t inhibit_any_policy)
{
    SSH_DEBUG(SSH_D_MIDSTART, ("Policy constrained to (exp=%d,ipm=%d,iap=%d)",
                               (int) explicit_policy,
                               (int) inhibit_policy_mappings,
                               (int) inhibit_any_policy));

    constraints->explicit_policy = explicit_policy;
    constraints->inhibit_any_policy = inhibit_any_policy;
    constraints->inhibit_policy_mapping = inhibit_policy_mappings;
}

void
ssh_cm_search_add_user_initial_policy(SshCMSearchConstraints constraints,
                                      char *policy_oid)
{
    char **tmp;

    SSH_DEBUG(SSH_D_MIDSTART, ("Look for policy OID \"%s\"", policy_oid));
    tmp =
      ssh_realloc(constraints->user_initial_policy_set,
                  constraints->user_initial_policy_set_size * sizeof(char *),
                  (1+constraints->user_initial_policy_set_size) *
                  sizeof(char *));
    if (tmp)
    {
        tmp[constraints->user_initial_policy_set_size] =
            ssh_strdup(policy_oid);
        constraints->user_initial_policy_set_size += 1;
        constraints->user_initial_policy_set = tmp;
    }
}

/* The result has to be valid thru this time period. 'not_before' is
   the time when query is assumed to be made, and it can not be in the
   future. It this is not called, current time is assumed. */
void ssh_cm_search_set_time(SshCMSearchConstraints constraints,
                            SshBerTime not_before,
                            SshBerTime not_after)
{
    SSH_DEBUG(SSH_D_MIDSTART, ("Time from %@ to %@",
                               ssh_ber_time_render, not_before,
                               ssh_ber_time_render, not_after));

    if (not_before) ssh_ber_time_set(&constraints->not_before, not_before);
    if (not_after)  ssh_ber_time_set(&constraints->not_after, not_after);
}

void ssh_cm_search_set_keys(SshCMSearchConstraints constraints,
                            SshCertDBKey *keys)
{
    SSH_DEBUG(SSH_D_MIDSTART, ("keys set."));
    constraints->keys = keys;
}

void ssh_cm_search_set_key_type(SshCMSearchConstraints constraints,
                                SshX509PkAlgorithm algorithm)
{
    SSH_DEBUG(SSH_D_MIDSTART, ("Key type (%u).", algorithm));
    constraints->pk_algorithm = algorithm;
}

void ssh_cm_search_set_key_usage(SshCMSearchConstraints constraints,
                                 SshX509UsageFlags flags)
{
    SSH_DEBUG(SSH_D_MIDSTART, ("Key usage (%u).", flags));
    constraints->key_usage_flags = flags;
}

void ssh_cm_search_set_path_length(SshCMSearchConstraints constraints,
                                   size_t path_length)
{
    SSH_DEBUG(SSH_D_MIDSTART, ("Path length (%u).", path_length));
    constraints->max_path_length = path_length;
}

void ssh_cm_search_force_local(SshCMSearchConstraints constraints,
                               bool cert, bool crl)
{
    SSH_DEBUG(SSH_D_MIDSTART, ("Use of cached cert = %s, crl = %s.",
                               (cert == true ? "true" : "false"),
                               (crl  == true ? "true" : "false")));

    constraints->local.cert = cert;
    constraints->local.crl  = crl;
}

void ssh_cm_search_set_trusted_set(SshCMSearchConstraints constraints,
                                   SshMPInteger trusted_set)
{
    SSH_ASSERT(constraints != NULL && trusted_set != NULL);

    SSH_DEBUG(
            SSH_D_MIDSTART, ("Trusted set %@", ssh_cm_render_mp, trusted_set));
    ssh_mprz_set(&constraints->trusted_roots.trusted_set, trusted_set);
}

void ssh_cm_search_set_trusted_not_after(SshCMSearchConstraints constraints,
                                         SshBerTime trusted_not_after)
{
    SSH_ASSERT(constraints != NULL && trusted_not_after != NULL);

    SSH_DEBUG(SSH_D_MIDSTART, ("Trust not after %@",
                               ssh_ber_time_render, trusted_not_after));
    ssh_ber_time_set(&constraints->trusted_roots.trusted_not_after,
                     trusted_not_after);
}

void ssh_cm_search_set_rule(SshCMSearchConstraints constraints,
                            SshCMSearchRule rule)
{
    SSH_DEBUG(SSH_D_MIDSTART, ("Use rule (%u).", rule));
    constraints->rule = rule;
}

void ssh_cm_search_set_group_mode(SshCMSearchConstraints constraints)
{
    SSH_DEBUG(SSH_D_MIDSTART, ("Group mode on."));
    constraints->group = true;
}

void ssh_cm_search_set_until_root(SshCMSearchConstraints constraints)
{
    SSH_DEBUG(SSH_D_MIDSTART, ("Look until trusted root."));
    constraints->upto_root = true;
}

void
ssh_cm_search_check_revocation(SshCMSearchConstraints constraints,
                               bool onoff)
{
    SSH_DEBUG(SSH_D_MIDSTART,
              ("Certificate search revocation check set: %s",
               onoff ? "on" : "off"));
    constraints->check_revocation = onoff;
}

void
ssh_cm_search_add_access_hints(SshCMSearchConstraints constraints,
                               const char *url)
{
    void *tmp;
    /* Note, the search may (or may not) fail later due to lack of
       URL. */
    SSH_DEBUG(SSH_D_MIDSTART, ("Look objects from \"%s\".", url));

    tmp = ssh_realloc(constraints->access,
                      constraints->num_access *
                      sizeof(*constraints->access),
                      (1 + constraints->num_access) *
                      sizeof(*constraints->access));
    if (tmp == NULL)
    {
        ssh_free(constraints->access);
        return;
    }
    constraints->access = tmp;
    constraints->access[constraints->num_access].url = ssh_strdup(url);
    constraints->access[constraints->num_access].pending = 0;
    constraints->access[constraints->num_access].done = 0;

    constraints->num_access++;
}

#ifdef SSHDIST_VALIDATOR_OCSP
void ssh_cm_search_set_ocsp_vs_crl(SshCMSearchConstraints constraints,
                                   SshCMOcspMode mode)
{

#ifdef DEBUG_LIGHT
    char *mode_str[] = {
      "No OCSP",
      "OCSP only",
      "Use CRLs if OCSP fails",
      "No OCSP check for end entity" };
    SSH_DEBUG(SSH_D_MIDSTART, ("Setting OCSP mode to '%s' for %p.",
                               mode_str[mode], constraints));
#endif /* DEBUG_LIGHT */

    constraints->ocsp_mode = mode;
}
#endif /* SSHDIST_VALIDATOR_OCSP */




/************ Main Certificate Manager Routines **/

static bool
ssh_cm_error_append_string(SshBuffer buffer_p,
                           const char *string1,
                           const char *string2)
{
    SshBufferStatus status;
    unsigned char zero = 0;

    status = ssh_buffer_append_cstrs(buffer_p, string1, string2, NULL);

    if (status == SSH_BUFFER_OK)
        status = ssh_buffer_append(buffer_p, &zero, 1);

    if (status != SSH_BUFFER_OK)
      return false;

    return true;
}

static void
ssh_cm_error_cert_type(SshCMCertificate cm_cert,
                       SshBuffer buffer_p)
{
    bool ok;

    if (ssh_cm_trust_is_root(cm_cert, NULL) == true)
    {
        ok = ssh_cm_error_append_string(buffer_p,
                                        "  Trust anchor CA:",
                                        NULL);
    }
    else
    {
        size_t path_length;
        bool critical;
        bool is_ca;

        if (ssh_x509_cert_get_basic_constraints(cm_cert->cert,
                                                &path_length,
                                                &is_ca,
                                                &critical) == false)
        {
            is_ca = false;
        }

        if (is_ca == true)
        {
            ok = ssh_cm_error_append_string(buffer_p,
                                            "  Intermediate CA:",
                                            NULL);
        }
        else
        {
            ok = ssh_cm_error_append_string(buffer_p,
                                            "  End entity certificate:",
                                            NULL);
        }
    }

    if (ok == false)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Cannot generate certificate type"));
    }
}

static void
ssh_cm_error_cert_subject_name(SshX509Certificate cert,
                               SshBuffer buffer_p)
{
    bool ok;
    SshStr str;

    /* Add suitable names. */
    ssh_x509_name_reset(cert->subject_name);

    ok = ssh_x509_cert_get_subject_name_str(cert, &str);
    if (ok == true)
    {
        char *name;
        size_t len;
        SshStr latin1 =
          ssh_str_charset_convert(str, SSH_CHARSET_ISO_8859_1);

        name = (char *)ssh_str_get(latin1, &len);
        ok = ssh_cm_error_append_string(buffer_p,
                                        "    Subject: ",
                                        name);
        ssh_str_free(latin1);
        ssh_free(name);
        ssh_str_free(str);
    }
    else
    {
        (void) ssh_cm_error_append_string(buffer_p,
                                          "    Subject: UNKNOWN",
                                          NULL);
    }

    if (ok == false)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Cannot generate subject"));
    }
}

static void
ssh_cm_error_cert_serial_number(SshX509Certificate cert,
                                SshBuffer buffer_p)
{
    SshMPIntegerStruct mp_integer;
    bool ok;

    ssh_mprz_init(&mp_integer);
    ok = ssh_x509_cert_get_serial_number(cert, &mp_integer);
    if (ok == true)
    {
        char * serial_number = ssh_mprz_get_str(&mp_integer, 10);

        ok = ssh_cm_error_append_string(buffer_p,
                                        "    Serial Number: ",
                                        serial_number);
        ssh_free(serial_number);
    }
    else
    {
        (void) ssh_cm_error_append_string(buffer_p,
                                          "    Serial Number: UNKNOWN",
                                          NULL);
    }

    ssh_mprz_clear(&mp_integer);

    if (ok == false)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Cannot generate serial number"));
    }
}

static void
ssh_cm_error_cert_issuer_name(SshX509Certificate cert,
                              SshBuffer buffer_p)
{
    char *name;
    bool ok;

    ssh_x509_name_reset(cert->issuer_name);

    ok = ssh_x509_cert_get_issuer_name(cert, &name);
    if (ok == true)
    {
        ok = ssh_cm_error_append_string(buffer_p,
                                        "    Issuer: ",
                                        name);
        ssh_free(name);
    }
    else
    {
        (void) ssh_cm_error_append_string(buffer_p,
                                          "    Issuer: UNKNOWN",
                                          NULL);
    }

    if (ok == false)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Cannot generate issuer"));
    }
}

static void
ssh_cm_error_cm_cert(SshCMCertificate cm_cert,
                     SshBuffer buffer_p)
{
    if (cm_cert != NULL && buffer_p != NULL)
    {
        ssh_cm_error_cert_type(cm_cert, buffer_p);

        ssh_cm_error_cert_serial_number(cm_cert->cert, buffer_p);

        ssh_cm_error_cert_subject_name(cm_cert->cert, buffer_p);

        ssh_cm_error_cert_issuer_name(cm_cert->cert, buffer_p);
    }
}

static void
ssh_cm_generate_error_string(SshCMSearchContext *search,
                             SshCMError error,
                             SshCMCertificate cm_cert_primary,
                             SshCMCertificate cm_cert_secondary)
{
    unsigned char *error_string = NULL;
    int error_string_len = 0;
    SshBufferStruct buffer;
    bool ok;
    int len;

    ssh_buffer_init(&buffer);

    ok = ssh_cm_error_append_string(&buffer,
                                    "Reason: ",
                                    ssh_find_keyword_name(ssh_cm_error_strs,
                                                          error));
    if (ok == false)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Cannot generate error"));
    }

    ssh_cm_error_cm_cert(cm_cert_primary, &buffer);

    ssh_cm_error_cm_cert(cm_cert_secondary, &buffer);

    len = ssh_buffer_len(&buffer);

    if (len > 0)
    {
        unsigned char double_zero[2] = { 0 };

        if (ssh_buffer_append(&buffer, double_zero, 2) == SSH_BUFFER_OK)
        {
            error_string =
              ssh_buffer_steal(&buffer, (size_t *) &error_string_len);
        }
    }

    ssh_buffer_uninit(&buffer);

    search->error_string = error_string;
    search->error_string_len = error_string_len;
}

void
ssh_cm_error_set(SshCMSearchContext *search,
                 unsigned int state,
                 SshCMError error,
                 SshCMCertificate cm_cert_primary,
                 SshCMCertificate cm_cert_secondary)
{
    search->state |= state;

    if (search->error == SSH_CM_OK)
    {
        /* Special case to handle error where OCSP and CRL has been failed. */
        if ((search->ocsp_check_failed == true) &&
            (error == SSH_CM_ERROR_CRL_NOT_FOUND))
        {
            error = SSH_CM_ERROR_REVOCATION_CHECK_FAILED_FROM_OCSP_AND_CRL;
        }

        search->error = error;

        ssh_cm_generate_error_string(search, error, cm_cert_primary,
                                     cm_cert_secondary);

        SSH_DEBUG(SSH_D_FAIL,
                  ("Certificate validation error = %s",
                   (search->error_string != NULL) ?
                   (char *) search->error_string : "null"));
    }
    else
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Certificate validation error already set, skip error = %s",
                   ssh_find_keyword_name(ssh_cm_error_strs, error)));
    }
}

/* Handle the searching list. */
static SshCMStatus
ssh_cm_add_search(SshCMContext cm,
                  SshCMSearchContext *search)
{
    SSH_DEBUG(SSH_D_HIGHSTART,
              ("New search to be added to the queue (%p).", search));

    if (cm->searching)
    {
        if (cm->current == NULL)
          SSH_NOTREACHED;

        cm->last->next = search;
        search->next = NULL;
        cm->last       = search;
    }
    else
    {
        if (cm->current != NULL)
          SSH_NOTREACHED;
        cm->current = search;
        cm->last    = search;
    }

    if (search->started == 0)
      search->started = ssh_time();

    /* We are thus now searching, and the current search can continue. */
    cm->searching = true;
    return SSH_CM_STATUS_OK;
}

static SshCMSearchContext *
ssh_cm_remove_search(SshCMContext cm,
                     SshCMSearchContext *op,
                     SshCMSearchContext *prev)
{
    SshCMSearchContext *tmp;

    SSH_DEBUG(SSH_D_HIGHSTART,
              ("Old search to be removed from the queue. (%p)", op));

    if (cm->searching)
    {
        if (op == NULL)
          /* searching but no current context available */
          SSH_NOTREACHED;

        tmp = op->next;
        /* Handle the removal. */
        if (prev)
          prev->next = tmp;
        else
          cm->current = tmp;
        if (tmp == NULL)
          cm->last = prev;

        if (cm->current == NULL)
        {
            cm->last = NULL;
            /* No longer searching. */
            cm->searching = false;
        }
        op->next = NULL;
    }
    else
    {
        /* remove attempt, but not searching. */
        SSH_NOTREACHED;
    }

    return op;
}

bool ssh_cm_searching(SshCMContext cm)
{
    return cm->searching;
}

static bool ssh_cm_init_local_cache(SshCMContext cm)
{
    SshCMConfig config = cm->config;

    if (config->local_db_allowed)
    {
        if (ssh_certdb_init(NULL_FNPTR,
                            NULL_FNPTR,
                            ssh_cm_data_free,
                            config->max_cache_entries,
                            config->max_cache_bytes,
                            config->default_time_lock,
                            (SshCMNotifyEvents) config->notify_events,
                            config->notify_context,
                            &cm->db) != SSH_CDBET_OK)
        {
            return false;
        }
    }

    return true;
}


SshCMContext ssh_cm_allocate(SshCMConfig config)
{
    SshCMContext cm = ssh_calloc(1, sizeof(*cm));
    bool edb_initialized = false;

    SSH_DEBUG(SSH_D_HIGHOK, ("Allocate certificate manager."));

    if (cm == NULL)
    {
        /* Always free config data. */
        ssh_cm_config_free(config);
        return NULL;
    }

    /* Initialize. */
    cm->config = config;
    cm->db     = NULL;

    /* Current status. */
    cm->operation_depth = 0;
    cm->session_id      = 1;
    cm->searching       = false;
    cm->in_callback     = 0;
    cm->current = cm->last = NULL;

    ssh_ber_time_zero(&cm->ca_last_revoked_time);

    /* Initialize the local cache. */
    if (ssh_cm_init_local_cache(cm) == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory cache initialization failed."));
        goto failed;
    }

    /* Allocate the certificate databases. */

    /* Initialize the negative cache. */
    cm->negacache =
      ssh_edb_nega_cache_allocate(cm->config->nega_cache_size,
                                  SSH_CM_KEY_TYPE_NUM,
                                  cm->config->nega_cache_invalid_secs);
    if (cm->negacache == NULL)
      goto failed;

    /* Initialize the operation table. */
    cm->op_map = ssh_cm_map_allocate();
    if (cm->op_map == NULL)
      goto failed;

    /* Set up the external database system. */
    if (!ssh_cm_edb_init(&cm->edb))
      goto failed;
    edb_initialized = true;

#ifdef SSHDIST_VALIDATOR_LDAP
    if (!ssh_cm_edb_ldap_init(cm, ""))
      goto failed;
#endif /* SSHDIST_VALIDATOR_LDAP */

    cm->control_timeout_active = false;
    cm->map_timeout_active = false;
    cm->next_op_expire_timeout = 0;

    ssh_fsm_init(cm->fsm, cm);
    return cm;

   failed:
    if (cm->db) ssh_certdb_free(cm->db);
    if (edb_initialized) ssh_cm_edb_free(&cm->edb);
    if (cm->negacache) ssh_edb_nega_cache_free(cm->negacache);
    if (cm->op_map) ssh_cm_map_free(cm->op_map);
    ssh_cm_config_free(config);
    ssh_free(cm);
    return NULL;
}

static void ssh_cm_map_timeout_control(void *context)
{
    SshCMContext cm = (SshCMContext) context;

    SSH_ASSERT(cm->map_timeout_active == true);
    cm->map_timeout_active = false;
    ssh_cm_operation_control(cm);
}

void ssh_cm_timeout_control(void *context)
{
    SshCMContext cm = (SshCMContext) context;

    SSH_ASSERT(cm->control_timeout_active == true);
    cm->control_timeout_active = false;
    ssh_cm_operation_control(cm);
}

static void ssh_cm_timeout_op_expire(void *context)
{
    SshCMContext cm = (SshCMContext) context;

    SSH_ASSERT(cm->next_op_expire_timeout > 0);
    cm->next_op_expire_timeout = 0;
    ssh_cm_operation_control(cm);
}

static void cm_cancel_timeouts(SshCMContext cm)
{
    if (cm->control_timeout_active)
    {
        ssh_cancel_timeout(&cm->control_timeout);
        cm->control_timeout_active = false;
    }

    if (cm->map_timeout_active)
    {
        ssh_cancel_timeout(&cm->map_timeout);
        cm->map_timeout_active = false;
    }

    if (cm->next_op_expire_timeout > 0)
    {
        ssh_cancel_timeout(&cm->op_expire_timeout);
        cm->next_op_expire_timeout = 0;
    }
}

static void cm_stopped(SshCMContext cm)
{
    cm_cancel_timeouts(cm);

    if (cm->stopped_callback)
    {
        (*cm->stopped_callback)(cm->stopped_callback_context);
    }

    cm->stopping = false;
    cm->stopped_callback = NULL_FNPTR;
}

static void cm_stop(void *context)
{
    SshCMContext cm = context;
    SshCMSearchContext *tmp;

    /* Terminate current searches. */
    for (tmp = cm->current; tmp; tmp = tmp->next)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Terminating search %p, status = %u",
                                tmp, tmp->terminated));
        if (!tmp->terminated)
        {
            cm_search_callback(tmp, SSH_CM_STATUS_STOPPED, NULL);
            tmp->terminated = true;
            ssh_cm_edb_operation_remove(cm, tmp);

            /* Abort asynchronous verify operation. */
            if (tmp->async_op != NULL)
            {
                SSH_ASSERT(tmp->waiting > 0);
                tmp->waiting -= 1;

                ssh_operation_abort(tmp->async_op);
                tmp->async_op = NULL;
            }
        }
    }
    ssh_cm_edb_stop(&cm->edb);
    ssh_cm_operation_control(cm);
}


void ssh_cm_stop(SshCMContext cm,
                 SshCMDestroyedCB callback, void *callback_context)
{
    /* Disable new searches. */
    cm->stopping = true;
    cm->stopped_callback = callback;
    cm->stopped_callback_context = callback_context;
    ssh_register_timeout(NULL, 0L, 0L, cm_stop, cm);
}

/* Must not be called before eventloop is uninitialized or the CM has
   been successfully stopped. */
void ssh_cm_free(SshCMContext cm)
{
    SSH_DEBUG(SSH_D_HIGHOK, ("Free certificate manager."));

    /* Cancel timeouts, in case being part of old application not
       calling ssh_cm_stop */
    cm_stopped(cm);

    ssh_cm_map_free(cm->op_map);

    ssh_certdb_free(cm->db);
    ssh_cm_edb_free(&cm->edb);
    ssh_edb_nega_cache_free(cm->negacache);

    ssh_cm_config_free(cm->config);

    ssh_free(cm);
}

/* Check whether the certificate has a been previously added to the
   database. */
bool
ssh_cm_check_db_collision(SshCMContext cm,
                          SshCMDataType type,
                          const unsigned char *ber, size_t ber_length,
                          SshCertDBKey **key,
                          unsigned int *entry_id)
{
    unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
    unsigned char *key_digest;
    size_t length;
    SshHash hash;
    SshCertDBEntryList *found;
    SshCertDBEntryListNode list;

    SSH_DEBUG(
            SSH_D_MIDOK,
            ("Collision check for (%s).",
             (type == SSH_CM_DATA_TYPE_CERTIFICATE ? "certificate" : "crl")));

    /* Set up the returned entry identifier for an error. */
    if (entry_id)
      *entry_id = 0;

    /* Error. */
    if (ber == NULL)
    {
        /* The certificate is not correct. */
        SSH_DEBUG(SSH_D_ERROR, ("DER of input to collision check is NULL."));
        return true;
    }

    /* Allocate hash algorithm. */
    if (ssh_hash_allocate(SSH_CM_HASH_ALGORITHM, &hash) != SSH_CRYPTO_OK)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Can't allocate %s", SSH_CM_HASH_ALGORITHM));
        return true;
    }

    ssh_hash_update(hash, ber, ber_length);
    ssh_hash_final(hash, digest);
    length = ssh_hash_digest_length(ssh_hash_name(hash));
    ssh_hash_free(hash);

    /* Use only 8 bytes maximum for this information, the hash function
       used is a very good one, thus even 2^64 different values should
       be enough for reasonably small amount of matches. */
    if (length > 8)
      length = 8;

    /* Try to find it from the database. */
    if (ssh_certdb_find(cm->db,
                        type,
                        SSH_CM_KEY_TYPE_BER_HASH,
                        digest, length,
                        &found) != SSH_CDBET_OK)
      /* If not found then clearly cannot be in the database. */
      goto add_key;

    /* It didn't found anything that we could use. */
    if (found == NULL)
      goto add_key;

    /* Seek through the table. We expect that collisions are possible with
       because our accuracy with the hash is just 64 bits. With larger size
       the probability would become so negligible that we wouldn't need this
       test. */
    for (list = found->head; list; list = list->next)
    {
        switch (type)
        {
          case SSH_CM_DATA_TYPE_CERTIFICATE:
          {
              SshCMCertificate cm_tmp_cert = list->entry->context;

              if (cm_tmp_cert->ber_length == ber_length)
              {
                  if (memcmp(cm_tmp_cert->ber, ber, ber_length) == 0)
                  {
                      /* Return the entry identifier also. */
                      if (entry_id)
                        *entry_id = cm_tmp_cert->entry->id;

                      ssh_certdb_entry_list_free_all(cm->db, found);
                      return true;
                }
              }
          }
            break;

          case SSH_CM_DATA_TYPE_CRL:
          {
              SshCMCrl cm_tmp_crl = list->entry->context;

              if (cm_tmp_crl->ber_length == ber_length)
              {
                  if (memcmp(cm_tmp_crl->ber, ber, ber_length) == 0)
                  {
                      /* CRL entry identifier. */
                      if (entry_id)
                        *entry_id = cm_tmp_crl->entry->id;

                      ssh_certdb_entry_list_free_all(cm->db, found);
                      return true;
                  }
              }
          }
            break;

          default:
            /* unsupported type, database corrupted */
            SSH_NOTREACHED;
            break;
        }
    }
    ssh_certdb_entry_list_free_all(cm->db, found);

    /* Add a key to the key list. */
   add_key:

    /* Check if the list actually is there. */
    if (key)
    {
        /* Was not found, thus push the hash to the key list. */
        key_digest = ssh_memdup(digest, length);
        /* Push to the list. */
        ssh_certdb_key_push(key, SSH_CM_KEY_TYPE_BER_HASH, key_digest, length,
                            false);
    }

    /* The thing was not found from the database. */
    return false;
}

/********************************************************/

static bool
cm_search_process_rule(SshCertDB db,
                       SshCMSearchRule rule,
                       SshCertDBEntryList **combined,
                       SshCertDBEntryList *result)
{
    /* Handle the new list which was found. */
    switch (rule)
    {
      case SSH_CM_SEARCH_RULE_AND:
        if (result == NULL || ssh_certdb_entry_list_empty(result))
          goto error;

        if (*combined == NULL)
        {
            *combined = result;
            break;
        }
        else
        {
            ssh_certdb_entry_list_intersect(db, *combined, result);
        }

        if (ssh_certdb_entry_list_empty(*combined))
          goto error;

        ssh_certdb_entry_list_free_all(db, result);
        break;

      case SSH_CM_SEARCH_RULE_OR:
        if (*combined == NULL)
        {
            *combined = result;
        }
        else
        {
            if (!ssh_certdb_entry_list_empty(result))
            {
                ssh_certdb_entry_list_union(db, *combined, result);
                ssh_certdb_entry_list_free_all(db, result);
            }
        }
        break;

      default:
        /* unsupported rule; application error */
        SSH_NOTREACHED;
        break;
    }

    return true;

   error:
    ssh_certdb_entry_list_free_all(db, result);
    ssh_certdb_entry_list_free_all(db, *combined);
    return false;
}

/* Searching from the local certificate cache. This will not consult
   external databases. */
static SshCMStatus
cm_search_local_cache(SshCMContext cm,
                      SshCMDataType type,
                      SshCertDBKey *keys,
                      SshCMSearchRule rule,
                      SshCertDBEntryList **ret_found)
{
    SshCertDBEntryList *combined = NULL, *result;
    bool ok;

    SSH_DEBUG(SSH_D_MIDOK,
              ("Local cache search (%s).",
               (type == SSH_CM_DATA_TYPE_CERTIFICATE
                ? "certificate" : "crl")));

    if (cm->db == NULL)
      return SSH_CM_STATUS_FAILURE;

    combined = NULL;
    for (; keys; keys = keys->next)
    {
        result = NULL;
        ssh_certdb_find(cm->db, type, keys->type, keys->data, keys->data_len,
                        &result);

        /* Do not consider access hint URI's as strict keys
           when looking up from local cache. */
        if (result == NULL && keys->access_hint == true)
          continue;

        ok = cm_search_process_rule(cm->db, rule, &combined, result);
        if (ok == false)
        {
            *ret_found = NULL;
            return SSH_CM_STATUS_NOT_FOUND;
        }
    }

    *ret_found = combined;

    if (combined == NULL)
      return SSH_CM_STATUS_NOT_FOUND;

    /* Success. */
    return SSH_CM_STATUS_OK;
}

/* Higher level routines for search from the local database.

   NOTE: these functions are not to be used when trusted data is
   searched for. This interface is given for implementations that want
   to investigate the local database. */

/* Updates entry list by removing certs that do not fill time
   constraints given at the search. */
static void
cm_check_cert_time_constraint(SshCertDB db,
                              SshCertDBEntryList *list,
                              SshCMSearchConstraints constraints)
{
    SshCertDBEntryListNode node, next;
    SshCertDBEntry *entry;

    for (node = list->head; node; node = next)
    {
        SshCMCertificate cm_cert = node->entry->context;
        SshX509Certificate cert = cm_cert->cert;

        next = node->next;

        if (ssh_ber_time_available(&constraints->not_before))
        {
            /* If it was issued after search start time? */
            if (ssh_ber_time_cmp(&constraints->not_before, &cert->not_before)
                < 0)
            {
                SSH_DEBUG(SSH_D_MIDOK,
                          ("Cert issued after search start time; %@ < %@",
                           ssh_ber_time_render, &cert->not_before,
                           ssh_ber_time_render, &constraints->not_before));

                entry = ssh_certdb_entry_list_remove(db, node);
                ssh_certdb_release_entry(db, entry);
                continue;
            }
        }
        /* If it expires before search end time ? */
        if (ssh_ber_time_available(&constraints->not_after))
        {
            if (ssh_ber_time_cmp(
                        &constraints->not_after, &cert->not_after) > 0)
            {
                SSH_DEBUG(SSH_D_MIDOK,
                          ("Cert expires before search end time; %@ < %@",
                           ssh_ber_time_render, &cert->not_before,
                           ssh_ber_time_render, &constraints->not_before));

                entry = ssh_certdb_entry_list_remove(db, node);
                ssh_certdb_release_entry(db, entry);
                continue;
            }
        }
    }
}

SshCMStatus
ssh_cm_find_local_cert(SshCMContext cm,
                       SshCMSearchConstraints constraints,
                       SshCMCertList *cert_list)
{
    SshCertDBEntryList *list;

    if (cm_search_local_cache(cm, SSH_CM_DATA_TYPE_CERTIFICATE,
                              constraints->keys,
                              constraints->rule,
                              cert_list) != SSH_CM_STATUS_OK)
    {
        ssh_cm_search_free(constraints);
        return SSH_CM_STATUS_NOT_FOUND;
    }

    list = *cert_list;
    cm_check_cert_time_constraint(cm->db, list, constraints);
    ssh_cm_search_free(constraints);

    /* Check if the list is actually empty. */
    if (ssh_certdb_entry_list_empty(list))
    {
        ssh_certdb_entry_list_free_all(cm->db, list);
        *cert_list = NULL;
        return SSH_CM_STATUS_NOT_FOUND;
    }
    return SSH_CM_STATUS_OK;
}


/* Append relative to DN kind of issuer */
static SshX509Name
cm_dp_make_full_name(SshX509Name issuer,
                     SshDN relative)
{
    SshX509Name full = NULL;
    unsigned char *i_der;
    size_t i_der_len;

    if (issuer && relative)
    {
        ssh_x509_name_reset(issuer);
        if (ssh_x509_name_pop_der_dn(issuer, &i_der, &i_der_len))
        {
            SshDNStruct fulldn;

            ssh_dn_init(&fulldn);
            (void)ssh_dn_decode_der(i_der, i_der_len, &fulldn, NULL);
            ssh_free(i_der);
            i_der = NULL;

            (void)ssh_dn_put_rdn(&fulldn, ssh_rdn_copy(*relative->rdn));
            (void) ssh_dn_encode_der(&fulldn, &i_der, &i_der_len, NULL);
            ssh_dn_clear(&fulldn);

            ssh_x509_name_push_directory_name_der(&full, i_der, i_der_len);
            ssh_free(i_der);
        }
    }
    return full;
}

SshCMStatus
ssh_cm_find_local_crl(SshCMContext cm,
                      SshCMSearchConstraints constraints,
                      SshCMCrlList *crl_list)
{
    SshCertDBEntryListNode node, next;
    SshCertDBEntryList *list;

    if (cm_search_local_cache(cm, SSH_CM_DATA_TYPE_CRL,
                              constraints->keys,
                              constraints->rule,
                              crl_list) != SSH_CM_STATUS_OK)
    {
        ssh_cm_search_free(constraints);
        return SSH_CM_STATUS_NOT_FOUND;
    }

    /* Now traverse the found list in order to determine whether all
       of these are really useful CRL's. However, we will not delete our
       sole CRL from the list. */
    list = *crl_list;
    for (node = list->head; node; node = next)
    {
        SshCMCrl cm_crl = node->entry->context;
        SshX509Crl crl;

        next = node->next;

        if (cm_crl->status_flags & SSH_CM_CRL_FLAG_SKIP)
        {
            /* Remove from the list. */
            ssh_certdb_entry_list_remove(cm->db, node);
            continue;
        }

        crl = cm_crl->crl;

        if (ssh_ber_time_available(&constraints->not_after))
        {
            /* CRL issued after our time of interest ends */
            if (ssh_ber_time_cmp(
                        &constraints->not_after, &crl->this_update) < 0)
            {
                /* Too new. */
                ssh_certdb_entry_list_remove(cm->db, node);
                continue;
            }
        }
        if (ssh_ber_time_available(&constraints->not_before))
        {
            /* CRL is only valid before our time of interest begins */
            if (ssh_ber_time_available(&crl->next_update) &&
                ssh_ber_time_cmp(&constraints->not_before, &crl->next_update)
                >= 0)
            {
                /* Too old. */
                ssh_certdb_entry_list_remove(cm->db, node);
                continue;
            }
        }
    }
    ssh_cm_search_free(constraints);

    /* Check if the list is actually empty. */
    if (ssh_certdb_entry_list_empty(list))
    {
        ssh_certdb_entry_list_free_all(cm->db, *crl_list);
        *crl_list = NULL;
        return SSH_CM_STATUS_NOT_FOUND;
    }

    return SSH_CM_STATUS_OK;
}


/**** The general search routine that finds everything. */

/* First search from local databases, that are fast to search. Then
   one can decide whether the information was sufficient and whether
   external database searches are needed. However, this needs to be
   taken care of by the above layer.

   There are reasons why this division have been made, mainly they are
   special cases where otherwise we would find ourselves in situations
   that end up as failures even if success would be possible. */

static SshCertDBEntryList *
cm_search_local_dbs(SshCMSearchContext *search,
                    SshCMDataType type,
                    SshCertDBKey *keys,
                    SshCMSearchRule rule)
{
    SshCertDBEntryList *combined = NULL, *result;
    SshCMDBDistinguisher *distinguisher;
    SshCMContext cm = search->cm;
    SshCertDBKey *key, *next_key;
    bool ok;

    SSH_DEBUG(
            SSH_D_MIDOK,
            ("Local database search for %s.",
             (type == SSH_CM_DATA_TYPE_CERTIFICATE ? "certificate" : "crl")));

    combined = NULL;
    for (key = keys; key != NULL; key = next_key)
    {
        next_key = key->next;
        result = NULL;

        /* The special case of searching from the local cache. Search
           always as it is fast, and usually we find what we are looking
           for. (If not then the time spent here didn't actually cost
           anything.) */
        ssh_certdb_find(cm->db, type, key->type, key->data, key->data_len,
                        &result);

        if (result == NULL)
        {
            /* Now try other locally configured db searching. */

            /* Create distinguisher. */
            distinguisher =
              ssh_cm_edb_distinguisher_allocate(type, keys->type, keys->data,
                                                keys->data_len);
            if (distinguisher == NULL)
            {
                ssh_certdb_entry_list_free_all(cm->db, combined);
                SSH_DEBUG(SSH_D_HIGHOK,
                          ("ssh.local: [failed] distinguisher alloc"));
                return NULL;
            }

            switch (ssh_cm_edb_search_local(search, distinguisher))
            {
              case SSH_CMEDB_OK:
                SSH_DEBUG(SSH_D_LOWOK,
                          ("Found from a local DB; retrying from the cache."));
                ssh_cm_edb_distinguisher_free(distinguisher);
                next_key = key;
                continue;

              case SSH_CMEDB_NOT_FOUND:
                SSH_DEBUG(SSH_D_LOWOK,
                          ("Local DB search failed for the distinguisher."));
                ssh_cm_edb_distinguisher_free(distinguisher);
                SSH_ASSERT(result == NULL);
                break;

              default:
                /* Unknown search result, possible implementation failure */
                SSH_NOTREACHED;
                break;
            }

            SSH_ASSERT(result == NULL);

            /* Do not consider access hint URI's as strict keys
               when looking up from local cache. */
            if (key->access_hint == true)
              continue;
        }

        /* Now we have something at the result. Combine the result
           with earlier results according to search rule. */
        ok = cm_search_process_rule(cm->db, rule, &combined, result);
        if (ok == false)
        {
            SSH_DEBUG(SSH_D_HIGHOK,
                      ("ssh.local: [failed] process rule."));
            return NULL;
        }
    }

    if (combined == NULL)
    {
        SSH_DEBUG(SSH_D_HIGHOK, ("ssh.local: [failed]."));
    }
    else
    {
        SSH_DEBUG(SSH_D_HIGHOK, ("ssh.local: [finished]."));
    }

    return combined;
}


static SshCMStatus
cm_search_dbs_with_dg(SshCMContext cm,
                      SshCMSearchContext *search,
                      SshCMDBDistinguisher *distinguisher,
                      SshCertDBEntryList **result)
{
    *result = NULL;

    switch (ssh_cm_edb_search(search, distinguisher))
    {
      case SSH_CMEDB_OK:
        /* Grab the object found from the cache, where the search
           routine puts objects found. */
        ssh_certdb_find(cm->db,
                        distinguisher->data_type,
                        distinguisher->key_type,
                        distinguisher->key, distinguisher->key_length,
                        result);
        ssh_cm_edb_distinguisher_free(distinguisher);
        return SSH_CM_STATUS_OK;

      case SSH_CMEDB_DELAYED:
      case SSH_CMEDB_SEARCHING:
        ssh_cm_edb_distinguisher_free(distinguisher);
        return SSH_CM_STATUS_SEARCHING;

      case SSH_CMEDB_NOT_FOUND:
        ssh_cm_edb_distinguisher_free(distinguisher);
        return SSH_CM_STATUS_NOT_FOUND;

      default:
        /* unknown search result; corruption */
        SSH_NOTREACHED;
        return SSH_CM_STATUS_NOT_FOUND;
    }
}

/* This function is the general search function that is called when
   ever things are needed. */
static SshCMStatus
cm_search_dbs(SshCMSearchContext *search,
              SshCMDataType type,
              SshCertDBKey *keys,
              SshCMSearchRule rule,
              SshCertDBEntryList **ret_found)
{
    SshCertDBEntryList *combined, *result;
    SshCMContext cm = search->cm;
    bool searching = false, failed = false;
    SshCMDBDistinguisher *distinguisher = NULL;
    SshCMStatus rv;
    bool ok;
    int i;

    SSH_DEBUG(
            SSH_D_MIDOK,
            ("Database search for %s.",
             (type == SSH_CM_DATA_TYPE_CERTIFICATE ? "certificate" : "crl")));

    *ret_found = NULL;

    /* First look from specified access locations - if any. Only after
       all locations have been done fallback to search made by keys. */
    for (i = 0; i < search->end_cert->num_access; i++)
    {
        if (search->end_cert->access[i].url != NULL
            && !search->end_cert->access[i].done)
        {
            const char *url = search->end_cert->access[i].url;
            unsigned char *key_data;
            size_t key_len;

            if (search->end_cert->access[i].pending)
              return SSH_CM_STATUS_SEARCHING;

            key_data = (unsigned char *) url;
            key_len = ssh_strlen(url);

            distinguisher =
              ssh_cm_edb_distinguisher_allocate(SSH_CM_DATA_TYPE_CERTIFICATE,
                                                SSH_CM_KEY_TYPE_URI,
                                                key_data,
                                                key_len);
            if (distinguisher == NULL)
              return SSH_CM_STATUS_NOT_FOUND;

            distinguisher->direct_access_id = i;
            rv = cm_search_dbs_with_dg(cm, search, distinguisher, &result);
            if (rv == SSH_CM_STATUS_SEARCHING)
            {
                search->end_cert->access[i].pending = true;
                *ret_found = NULL;
            }
            else
            {
                *ret_found = result;
            }
            return rv;
        }
    }

    /* Initialize the found values computation. */
    combined = NULL;
    for (; keys != NULL; keys = keys->next)
    {
        result = NULL;

        /* In CRL case, start external database search only for CRL URIs. */
        if (type == SSH_CM_DATA_TYPE_CRL &&
            keys->type == SSH_CM_KEY_TYPE_URI &&
            keys->crl_uri == false)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Skip key: %@",
                       ssh_cm_render_cert_db_key, keys));
            continue;
        }

        /* Now try external database search, first create distinguisher. */
        distinguisher =
          ssh_cm_edb_distinguisher_allocate(type, keys->type, keys->data,
                                            keys->data_len);
        if (distinguisher == NULL)
        {
            ssh_certdb_entry_list_free_all(cm->db, combined);
            return SSH_CM_STATUS_NOT_FOUND;
        }

        rv = cm_search_dbs_with_dg(cm, search, distinguisher, &result);
        if (rv == SSH_CM_STATUS_SEARCHING)
        {
            SSH_ASSERT(result == NULL);
            searching = true;
        }
        else
        {
            ok = cm_search_process_rule(cm->db, rule, &combined, result);
            if (ok == false)
            {
                SSH_ASSERT(combined == NULL);
                failed = true;
            }
        }
    }

    if (failed == true)
    {
        ssh_certdb_entry_list_free_all(cm->db, combined);
        combined = NULL;
    }

    *ret_found = combined;

    if (searching == true)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Search external DB's spawned."));
        return SSH_CM_STATUS_SEARCHING;
    }

    if (combined == NULL)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Search external DB's using keys was a failure."));
        return SSH_CM_STATUS_NOT_FOUND;
    }

    SSH_DEBUG(SSH_D_HIGHOK, ("Search external DB's was a success."));
    return SSH_CM_STATUS_OK;
}

static SshCMStatus
ssh_cm_compute_validity_times(SshCMSearchContext *search)
{
    SshCMContext               cm = search->cm;
    SshCMSearchConstraints constraints = search->end_cert;
    SshTime                   now;

    SSH_DEBUG(SSH_D_HIGHSTART,
              ("Compute validity times and get the current time."));

    now = (*cm->config->time_func)(cm->config->time_context);

    if (ssh_ber_time_available(&constraints->not_before))
      now = ssh_ber_time_get_unix_time(&constraints->not_before);

    /* First, set current time from system clock. This may be changed by
       the current search constraints */
    ssh_ber_time_set_from_unix_time(&search->cur_time, now);

    if (now)
    {
        ssh_ber_time_set(&search->valid_time_start, &search->cur_time);
        ssh_ber_time_set_from_unix_time(&search->max_cert_validity_time,
                                        now + cm->config->max_validity_secs);
        ssh_ber_time_set_from_unix_time(
                &search->max_crl_validity_time,
                now + cm->config->min_crl_validity_secs);
    }

    if (ssh_ber_time_available(&constraints->not_after))
      ssh_ber_time_set(&search->valid_time_end, &constraints->not_after);
    else
      ssh_ber_time_set(&search->valid_time_end,
                       &search->max_cert_validity_time);

    return SSH_CM_STATUS_OK;
}

/* current is the current certificate being considered on path
   building.  previous is the head of found so far, that is base cert
   for issuer search (or NULL if for_end_cert is set). Constraints set
   by previous will be enforced on the subject. */
static SshCMStatus
ssh_cm_cert_apply_constraints(SshCMSearchContext *search,
                              SshCMCertificate current,
                              SshCMCertificate previous,
                              bool for_end_cert)
{
    SshCMContext cm = search->cm;
    SshCMSearchConstraints constraints = search->end_cert;
    SshBerTimeStruct cert_not_before, cert_not_after;
    bool critical;

    SSH_DEBUG(SSH_D_HIGHOK, ("Applying constraints: Time is '%@'.",
                             ssh_ber_time_render, &search->cur_time));

    /* Check whether the certificate must be removed always from the
       search list! */

    /* check allowed algorithms */
    if (ssh_cm_cert_check_allowed_algorithms(
                              cm->config,
                              current->cert) == false)
    {
        SSH_DEBUG(SSH_D_NETFAULT, ("Algorithm not allowed."));
        ssh_cm_error_set(search,
                         SSH_CM_SSTATE_ALGORITHM_NOT_ALLOWED,
                         SSH_CM_ERROR_CERT_ALGORITHM_STRENGTH_TOO_WEAK,
                         current,
                         NULL);
        return SSH_CM_STATUS_CANNOT_BE_VALID;
    }

    /* Check first if the certificate is revoked. */
    if (constraints->check_revocation
        && current->status == SSH_CM_VS_REVOKED
        && !ssh_cm_trust_is_valid(current, search))
    {
        SSH_DEBUG(SSH_D_NETFAULT, ("Cert is revoked."));
        ssh_cm_error_set(search,
                         SSH_CM_SSTATE_CERT_REVOKED,
                         SSH_CM_ERROR_CERT_REVOKED,
                         current,
                         NULL);
        return SSH_CM_STATUS_CANNOT_BE_VALID;
    }

    /* The hard time limit is given here. */

    ssh_ber_time_zero(&cert_not_before);
    ssh_ber_time_zero(&cert_not_after);

    /* Check the certificate dates. */
    if (ssh_x509_cert_get_validity(current->cert,
                                   &cert_not_before,
                                   &cert_not_after) == false)
    {
        SSH_DEBUG(SSH_D_NETFAULT,
                  ("Cert validity times not available."));
        ssh_cm_error_set(search,
                         SSH_CM_SSTATE_CERT_INVALID,
                         SSH_CM_ERROR_CERT_INVALID,
                         current,
                         NULL);
        return SSH_CM_STATUS_CANNOT_BE_VALID;
    }

    /* Check the times. */
    if ((ssh_ber_time_available(&search->valid_time_start)
         && (ssh_ber_time_cmp(&cert_not_before, &search->valid_time_start) >= 0
             ||
             ssh_ber_time_cmp(
                     &cert_not_after,  &search->valid_time_start) < 0))
        ||
        ((ssh_ber_time_available(&search->valid_time_end)
          && (ssh_ber_time_cmp(&cert_not_before, &search->valid_time_end) > 0
              ||
              ssh_ber_time_cmp(
                      &cert_not_after,  &search->valid_time_end) <= 0)))
        )
    {
        /* Cannot succeed, as this certificate does not allow the full
           search interval to be applied. */
        SSH_DEBUG(SSH_D_NETFAULT,
                  ("Cert is not within search interval."));
        ssh_cm_error_set(search,
                         SSH_CM_SSTATE_CERT_NOT_IN_INTERVAL,
                         SSH_CM_ERROR_CERT_NOT_IN_INTERVAL,
                         current,
                         NULL);
        return SSH_CM_STATUS_CANNOT_BE_VALID;
    }

    /* Check if we can optimize the search with additional constraints
       for the end certificate. */
    if (for_end_cert)
    {
        SshX509Certificate cert = current->cert;

        if (constraints->pk_algorithm != SSH_X509_PKALG_UNKNOWN &&
            cert->subject_pkey.pk_type != constraints->pk_algorithm)
        {
            SSH_DEBUG(SSH_D_NETFAULT,
                      ("Cert pubkey algorithm did not match the search "
                       "constraints."));
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_ALG_MISMATCH,
                             SSH_CM_ERROR_CERT_ALGORITHM_MISMATCH,
                             current,
                             NULL);
            return SSH_CM_STATUS_CANNOT_BE_VALID;
        }

        if (constraints->key_usage_flags != 0)
        {
            SshX509UsageFlags flags;

            if (ssh_x509_cert_get_key_usage(cert, &flags, &critical))
            {
                if (flags != 0 && (flags & constraints->key_usage_flags) == 0)
                {
                    SSH_DEBUG(SSH_D_NETFAULT,
                              ("Cert key usage did not match the search "
                               "constraints."));
                    ssh_cm_error_set(search,
                                     SSH_CM_SSTATE_CERT_KEY_USAGE_MISMATCH,
                                     SSH_CM_ERROR_CERT_KEY_USAGE_MISMATCH,
                                     current,
                                     NULL);
                    return SSH_CM_STATUS_CANNOT_BE_VALID;
                }
            }
        }
    }

    if (previous)
    {
        if (!cm_verify_issuer_name(previous, current) ||
            !cm_verify_issuer_id(previous, current))
        {
            SSH_DEBUG(SSH_D_NETFAULT,
                      ("Issuer name or key identifier does not match "
                       "constraints set by subject; "
                       "offending certificates %@ and %@",
                       ssh_cm_render_certificate, current->cert,
                       ssh_cm_render_certificate, previous->cert));
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_CA_INVALID,
                             SSH_CM_ERROR_CERT_CA_INVALID,
                             current,
                             NULL);
            return SSH_CM_STATUS_CANNOT_BE_VALID;
        }
    }

    /* Should the certificate be trusted for the full validity period? */
    if (ssh_cm_trust_is_root(current, search) == true)
    {
        /* Note; it would be impossible to get here if the given
           certificate would not be a trusted root. However, we check here
           for the case that the certificate is a revoked by a trusted
           certificate. */
        if (constraints->check_revocation
            && !ssh_cm_trust_is_valid(current, search)
            && current->revocator_was_trusted)
        {
            SSH_DEBUG(SSH_D_NETFAULT,
                      ("Trust anchor %@ was revoked by another trust-anchor.",
                       ssh_cm_render_certificate, current->cert));
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_INVALID,
                             SSH_CM_ERROR_CERT_INVALID,
                             current,
                             NULL);
            return SSH_CM_STATUS_CANNOT_BE_VALID;
        }
        goto check_ca;
    }

    /* Check if a CA has been revoked recently. In such a case no
       certificate is valid until proven so. The problem here is that
       such a recomputation can be very time consuming. We'd like to
       avoid it as much as possible... */
    if (ssh_ber_time_cmp(&cm->ca_last_revoked_time,
                         &current->trusted.trusted_computed) >= 0)
    {
        /* We could check the validity period within the actual certificate
           here also. */
        SSH_DEBUG(SSH_D_MIDOK,
                  ("Possibly a CA has been revoked before trust computation "
                   "took place, hence recomputing trust."));
        return SSH_CM_STATUS_NOT_VALID;
    }

    /* Check the validity period, if the certificate has been recently
       checked. */
    if (ssh_cm_trust_check(current, NULL, search))
    {
        /* Check the times. */
        if ((ssh_ber_time_available(&search->valid_time_start)
             && (ssh_ber_time_cmp(&current->trusted.valid_not_before,
                                  &search->valid_time_start) >= 0
                 ||
                 ssh_ber_time_cmp(&current->trusted.valid_not_after,
                                  &search->valid_time_start) < 0))
            ||
            (ssh_ber_time_available(&search->valid_time_end)
             && (ssh_ber_time_cmp(&current->trusted.valid_not_before,
                                  &search->valid_time_end) > 0
                 ||
                 ssh_ber_time_cmp(&current->trusted.valid_not_after,
                                  &search->valid_time_end) <= 0)))
        {
            SSH_DEBUG(SSH_D_NETFAULT,
                      ("Trusted certificate was not valid in "
                       "the computed interval."));

            SSH_DEBUG(
                    SSH_D_NETFAULT,
                    ("Trusted during interval '%@' -> '%@'",
                     ssh_ber_time_render, &current->trusted.valid_not_before,
                     ssh_ber_time_render, &current->trusted.valid_not_after));

            SSH_DEBUG(SSH_D_NETFAULT,
                      ("Requested interval '%@' -> '%@'",
                       ssh_ber_time_render, &search->valid_time_start,
                       ssh_ber_time_render, &search->valid_time_end));

            /* The trust computation might lead to a better path. */
            return SSH_CM_STATUS_NOT_VALID;
        }

        SSH_DEBUG(SSH_D_MIDOK,
                  ("Certificate trusted until '%@'",
                   ssh_ber_time_render, &current->trusted.trusted_not_after));

        if (ssh_ber_time_cmp(&current->trusted.trusted_not_after,
                             &search->cur_time) < 0)
        {
            SSH_DEBUG(
                    SSH_D_NETFAULT,
                    ("Trusted certificate was not trusted at present time."));
            return SSH_CM_STATUS_NOT_VALID;
        }
    }

   check_ca:

    /* Check if the search is upto trusted roots. */
    if (constraints->upto_root)
      if (ssh_cm_trust_is_root(current, search) == false)
      {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("Not a trusted root certificate (terminated chain)."));
          return SSH_CM_STATUS_NOT_VALID;
      }

    /* Are we searching for a path to some particular CA? */
    if (search->ca_cert != NULL)
    {
        SshCertDBEntryListNode tmp;
        for (tmp = search->ca_cert->head; tmp; tmp = tmp->next)
        {
            if (tmp->entry->context == current)
            {
                /* We have found the correct CA. Thus we are on the
                   right path. And because this CA has been found
                   before (with same parameters) it holds that
                   the path validation can be called. */
                return SSH_CM_STATUS_OK;
            }

            /* Not found yet. */
        }
        SSH_DEBUG(SSH_D_MIDOK, ("Selected CA was not yet found."));
        /* Cannot be valid until the correct CA is found! */
        return SSH_CM_STATUS_NOT_VALID;
    }

    /* Not valid path yet. */
    return SSH_CM_STATUS_OK;
}


/* Function for handling the notification of events. */
static void
cm_notify_cert(SshCMContext cm, unsigned int event, SshCMCertificate subject)
{
    if (cm != NULL &&
        cm->config->notify_events != NULL &&
        cm->config->notify_events->certificate != NULL_FNPTR)
    {
        cm->in_callback++;
        (*cm->config->notify_events->certificate)
          (cm->config->notify_context, event, subject);
        cm->in_callback--;
    }
}

/* Revoked certificates are kept in a hash table indexed by serial
   number. One hash table is kept per CRL stored. For each revoked
   entry we store serial and revocation date and reason. */

typedef struct SshCMRevokedRec
{
    /* Concrete header and object model. */
    SshADTMapHeaderStruct adt_header;

    SshMPIntegerStruct serial;
    SshBerTimeStruct revocation;
    SshX509CRLReasonCode reason;
    uint32_t hash;
} *SshCMRevoked, SshCMRevokedStruct;

static uint32_t
cm_revoked_hash(const void *object, void *context)
{
    SshCMRevoked r = (SshCMRevoked) object;
    uint32_t h = 0;
    size_t len, i;
    unsigned char linear[64] = { 0 };

    if (r->hash == 0)
    {
        len = ssh_mprz_get_buf(linear, sizeof(linear), &r->serial);
        if (len != 0)
        {
            for (i = 0; i < len; i++)
              h = linear[i] ^ ((h << 7) | (h >> 26));
        }
        r->hash = h;
    }
    return r->hash;
}

static int
cm_revoked_compare(const void *object1, const void *object2,
                   void *context)
{
    SshCMRevoked r1 = (SshCMRevoked) object1;
    SshCMRevoked r2 = (SshCMRevoked) object2;

    return ssh_mprz_cmp(&r1->serial, &r2->serial);
}

static void
cm_revoked_destroy(void *object, void *context)
{
    SshCMRevoked r = (SshCMRevoked) object;

    ssh_mprz_clear(&r->serial);
    ssh_free(r);
}

void ssh_cm_cert_revoke(SshCMSearchContext *search,
                        SshCMCertificate ca,
                        SshCMCertificate subject,
                        SshCMRevoked revoked)
{
    SshCMContext cm = search->cm;

    if (subject->acting_ca)
    {
        /* We set here the time of last CA revocation to
           the current time. It could be tried to get
           from the actual dates in the revocation
           information. However, we don't entirely know
           whether it is in future or in past or
           whatever. It might be safest to use just
           the current time. */
        ssh_ber_time_set(&cm->ca_last_revoked_time,
                         &search->cur_time);
    }

    switch (revoked->reason)
    {
      case SSH_X509_CRLF_CERTIFICATE_HOLD:
        /* The certificate is on hold. */
        SSH_DEBUG(SSH_D_NETFAULT,
                  ("Certificate on hold: %@",
                   ssh_cm_render_certificate, subject->cert));

        /* Make it unsafe nevertheless. */
        subject->status = SSH_CM_VS_HOLD;
        /* Set crl_recompute_after in subject from ca. This is checked when
           we find suspended certificate from cache to determine if its
           suspension status should be rechecked from its issuer. */
        ssh_ber_time_set(&subject->crl_recompute_after,
                         &ca->crl_recompute_after);
        cm_notify_cert(cm, SSH_CM_EVENT_CERT_REVOKED, subject);
        break;
      case SSH_X509_CRLF_REMOVE_FROM_CRL:
        /* It is apparently not on CRL anymore. */
        SSH_DEBUG(SSH_D_HIGHOK,
                  ("Certificate removed from CRL: %@",
                   ssh_cm_render_certificate, subject->cert));
        break;
      default:

        /* Revoked! */
        SSH_DEBUG(SSH_D_NETFAULT,
                  ("Certificate revoked: %@",
                   ssh_cm_render_certificate, subject->cert));

        /* The certificate is revoked. */
        subject->status = SSH_CM_VS_REVOKED;
        if (ssh_cm_trust_is_root(ca, search))
          subject->revocator_was_trusted = true;
        ssh_cm_trust_make_user(subject, search);

        ssh_ber_time_set(&subject->trusted.trusted_not_after,
                         &revoked->revocation);
        /* Let the application know of the revocation. */
        cm_notify_cert(cm, SSH_CM_EVENT_CERT_REVOKED, subject);
        break;
    }
}

static void
ssh_cm_crl_initial_cert_transform(SshCMSearchContext *search,
                                  SshCMCertificate ca,
                                  SshCMCertificate subject)
{
    SSH_DEBUG(SSH_D_LOWOK,
              ("Initial transform for %@",
               ssh_cm_render_certificate, subject->cert));

    switch (subject->status)
    {
      case SSH_CM_VS_HOLD:
        /* Remove the hold status as the CRL did not contain
           the certificate anymore. */
        SSH_DEBUG(SSH_D_MIDOK,
                  ("Hold status reset for %@",
                   ssh_cm_render_certificate, subject->cert));
        subject->status = SSH_CM_VS_OK;
        break;
      case SSH_CM_VS_OK:
        break;
      default:
        break;
    }
}

/* Handle revocation in this function.
   Return values: 0 -> error, crl is invalid
                  1 -> ok, crl is for this certificate and was processed.
                  2 -> ok, crl is valid, but not for this certificate.
 */
static int
cm_crl_revoke(SshCMSearchContext *search,
              SshCMCrl cm_crl,
              SshCMCertificate ca,
              SshCMCertificate subject,
              SshX509ReasonFlags *reasons)
{
    SshCMContext cm = search->cm;
    SshX509Crl   crl;
    SshX509RevokedCerts revoked, next_revoked;
    SshCertDBEntryList *found;
    SshCertDBEntryListNode tmp;
    SshADTHandle handle;
    SshCMRevoked r;
    SshX509UsageFlags flags;
    bool critical;

    if (ssh_x509_cert_get_key_usage(ca->cert, &flags, &critical))
    {
        if (flags != 0 && (flags & SSH_X509_UF_CRL_SIGN) == 0)
        {
            SSH_DEBUG(
                    SSH_D_FAIL, ("Issuer of CRL is not allowed to sign CRL"));
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CRL_INVALID,
                             SSH_CM_ERROR_CRL_INVALID,
                             ca,
                             subject);
            return 0;
        }
    }

    /* Get the X.509 crl. */
    crl    = cm_crl->crl;

    /* Dump the found CRL. */
    SSH_DEBUG(SSH_D_MIDOK, ("Found CRL: %@", ssh_cm_render_crl, crl));

    ssh_ber_time_set(&ca->crl_recompute_after, &search->max_crl_validity_time);

    /* Set the new CRL recompute after values. */
    if (ssh_ber_time_available(&crl->next_update))
    {
        if (ssh_ber_time_cmp(&crl->next_update, &search->cur_time) > 0)
        {
            if (ssh_ber_time_cmp(&crl->next_update,
                                 &ca->crl_recompute_after) < 0)
            {
                ssh_ber_time_set(&ca->crl_recompute_after, &crl->next_update);
                SSH_DEBUG(SSH_D_LOWOK,
                          ("Adjusting CRL recomputation time to '%@'.",
                           ssh_ber_time_render, &ca->crl_recompute_after));
            }
        }
        else
        {
            SSH_DEBUG(SSH_D_NETFAULT,
                      ("This CRL is not valid at requested time."));

            /* In this case, that is, we have the latest CRL which is
               still not valid! We can only deduce if no other CRL's can
               be found, from external databases, then this path
               validation process must terminate as non-valid. */
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CRL_INVALID,
                             SSH_CM_ERROR_CRL_INVALID,
                             ca,
                             subject);
            ssh_ber_time_set(&ca->crl_recompute_after, &search->cur_time);
            return 0;
        }
    }

    SSH_DEBUG(SSH_D_LOWOK,
              ("CRL recomputation time set to '%@'.",
               ssh_ber_time_render, &ca->crl_recompute_after));

    /* Check through the X.509 CRL extensions. */
  {
      SshX509ExtIssuingDistPoint  idp;
      SshX509Certificate          subject_cert;
      SshMPIntegerStruct          delta;

      /* Determine the X.509 certificate of the subject. */
      if (ssh_cm_cert_get_x509(subject, &subject_cert) != SSH_CM_STATUS_OK)
      {
          SSH_DEBUG(SSH_D_FAIL, ("Can't get DER out of CMI certificate."));
          ssh_cm_error_set(search,
                           SSH_CM_SSTATE_CERT_INVALID,
                           SSH_CM_ERROR_CERT_INVALID,
                           ca,
                           subject);
          return 0;
      }
      ssh_mprz_init(&delta);
      if (ssh_x509_crl_get_delta_crl_indicator(crl, &delta, &critical))
      {
          ssh_x509_cert_free(subject_cert);
          SSH_DEBUG(SSH_D_FAIL, ("Delta CRL is not supported."));
          ssh_cm_error_set(search,
                           SSH_CM_SSTATE_CRL_INVALID,
                           SSH_CM_ERROR_CRL_INVALID,
                           ca,
                           subject);
          ssh_mprz_clear(&delta);
          return 0;
      }
      ssh_mprz_clear(&delta);

      /* Issuing distribution point. */
      if (ssh_x509_crl_get_issuing_dist_point(crl, &idp, &critical))
      {
          bool is_ca, matches_subject, free_full_idp;
          size_t  path_length, der_len;
          SshX509ExtCRLDistPoints cdp, p;
          unsigned char *der;
          char *idpuri;
          SshX509Name full_idp;

          if (critical != true)
          {
              /* CRL issuing distribution points should be critical. */
              ssh_x509_cert_free(subject_cert);
              SSH_DEBUG(SSH_D_NETFAULT, ("IssuingDP not critical on CRL."));
              ssh_cm_error_set(search,
                               SSH_CM_SSTATE_CRL_INVALID,
                               SSH_CM_ERROR_CRL_INVALID,
                               ca,
                               subject);
              return 0;
          }
          /* Check if this IDP is for the subject certificate, e.g IDP
             matches what is stated in the subject certificate. */
          if (!ssh_x509_cert_get_crl_dist_points(subject_cert,
                                                 &cdp, &critical))
          {
              cdp = NULL;
          }

          free_full_idp = false;
          if (idp->dn_relative_to_issuer)
          {
              full_idp = cm_dp_make_full_name(subject_cert->issuer_name,
                                              idp->dn_relative_to_issuer);
              free_full_idp = true;
          }
          else if (idp->full_name)
          {
              full_idp = idp->full_name;
          }
          else
          {
              full_idp = NULL;
          }

          /* If IDP contains a full name of the distributionPoint, check that
             a matching name is found from certificate. */
          if (full_idp)
          {
              matches_subject = false;

              if (!cdp)
              {
                  if (free_full_idp) ssh_x509_name_free(full_idp);
                  ssh_x509_cert_free(subject_cert);
                  SSH_DEBUG(SSH_D_NETFAULT,
                            ("IssuingDP on CRL but subject does not utilize "
                             "multiple CDP's."));
                  ssh_cm_error_set(search,
                                   SSH_CM_SSTATE_CRL_INVALID,
                                   SSH_CM_ERROR_CRL_INVALID,
                                   ca,
                                   subject);
                  return 2;
              }

              /* First loop to check whether we have a matching DN */
              ssh_x509_name_reset(full_idp);
              while (ssh_x509_name_pop_directory_name_der(full_idp,
                                                          &der, &der_len))
              {
                  for (p = cdp; p; p = p->next)
                  {
                      bool free_full_cdp = false;
                      SshX509Name full_cdp = NULL;

                      /* CRL's issuer must match CRL issuer if any */
                      if (p->crl_issuer)
                      {
                          if (!cm_name_equal(p->crl_issuer,
                                             crl->issuer_name))
                          {
                              SSH_DEBUG(SSH_D_MIDOK,
                                        ("Certificate indicated CRL issuer "
                                         "does not match this CRL's issuer."));
                              continue;
                          }
                      }

                      if (p->full_name == NULL)
                      {
                          full_cdp =
                            cm_dp_make_full_name(subject_cert->issuer_name,
                                                 p->dn_relative_to_issuer);
                          free_full_cdp = true;
                      }
                      else
                        full_cdp = p->full_name;

                      /* Distribution point name must match */
                      if (full_cdp->ber_len == der_len &&
                          memcmp(der, full_cdp->ber, der_len) == 0)
                      {
                          if (free_full_cdp)
                            ssh_x509_name_free(full_cdp);
                          matches_subject = true;
                          ssh_free(der);
                          goto foundit;
                      }
                      if (free_full_cdp)
                        ssh_x509_name_free(full_cdp);
                  }
                  ssh_free(der);
              }

              /* Second loop to check whether we have a matching URI */
              ssh_x509_name_reset(full_idp);
              while (ssh_x509_name_pop_uri(idp->full_name, &idpuri))
              {
                  for (p = cdp; p; p = p->next)
                  {
                      char *cdpuri;
                      size_t cdpuri_len; /* ignored */

                      if (p->full_name == NULL || p->full_name->name == NULL ||
                          (cdpuri =
                           ssh_str_get(
                                   p->full_name->name, &cdpuri_len)) == NULL)
                        continue;

                      if (0 == strcmp(idpuri, (char *)cdpuri))
                      {
                          matches_subject = true;
                          ssh_free(cdpuri); ssh_free(idpuri);
                          goto foundit;
                      }
                      ssh_free(cdpuri);
                  }
                  ssh_free(idpuri);
              }

            foundit:
              ssh_x509_name_reset(idp->full_name);
              if (free_full_idp)
                ssh_x509_name_free(full_idp);

              if (!matches_subject)
              {
                  ssh_x509_cert_free(subject_cert);
                  SSH_DEBUG(SSH_D_NETFAULT,
                            ("IssuingDP does not match the subject "
                             "certificate."));
                  ssh_cm_error_set(search,
                                   SSH_CM_SSTATE_CRL_INVALID,
                                   SSH_CM_ERROR_CRL_INVALID,
                                   ca,
                                   subject);
                  return 2;
              }
          }

          /* Get the basic constraints. */
          if (!ssh_x509_cert_get_basic_constraints(subject_cert,
                                                   &path_length,
                                                   &is_ca,
                                                   &critical))
            is_ca = false;

          ssh_x509_cert_free(subject_cert);

          /* Check that they conform to the flags. */
          if (idp->only_contains_attribute_certs)
          {
              SSH_DEBUG(SSH_D_NETFAULT,
                        ("IssuingDP for attributeCerts only."));
              ssh_cm_error_set(search,
                               SSH_CM_SSTATE_CRL_INVALID,
                               SSH_CM_ERROR_CRL_INVALID,
                               ca,
                               subject);
              return 2;
          }

          if (idp->only_contains_user_certs && is_ca == true)
          {
              SSH_DEBUG(SSH_D_NETFAULT,
                        ("IssuingDP for userCerts, subjectCert is CA."));
              ssh_cm_error_set(search,
                               SSH_CM_SSTATE_CRL_INVALID,
                               SSH_CM_ERROR_CRL_INVALID,
                               ca,
                               subject);
              return 2;
          }

          if (idp->only_contains_ca_certs && is_ca == false)
          {
              SSH_DEBUG(SSH_D_NETFAULT,
                        ("IssuingDP for CaCerts, subjectCert is User."));
              ssh_cm_error_set(search,
                               SSH_CM_SSTATE_CRL_INVALID,
                               SSH_CM_ERROR_CRL_INVALID,
                               ca,
                               subject);
              return 2;
          }

          /* Check the reason flags. */
          if (idp->only_some_reasons != 0)
            /* Which reasons? */
            *reasons |= idp->only_some_reasons;
          else
            /* All reasons. */
            *reasons |= 0x80ff;
      }
      else
      {
          /* No issuing distribution point -> all reasons. */
          ssh_x509_cert_free(subject_cert);
          *reasons |=  0x80ff;
      }
  }

    /* Create revoked mapping on the cm_crl entry. */
    if (cm_crl->revoked == NULL)
    {
        unsigned char *issuer_name_der, digest[SSH_MAX_HASH_DIGEST_LENGTH];
        size_t issuer_name_der_len, digest_len;
        SshHash hash;

        cm_crl->revoked =
          ssh_adt_create_generic(SSH_ADT_MAP,
                                 SSH_ADT_HASH,    cm_revoked_hash,
                                 SSH_ADT_COMPARE, cm_revoked_compare,
                                 SSH_ADT_DESTROY, cm_revoked_destroy,
                                 SSH_ADT_HEADER,
                                 SSH_ADT_OFFSET_OF(SshCMRevokedStruct,
                                                   adt_header),
                                 SSH_ADT_ARGS_END);
        if (cm_crl->revoked == NULL)
        {
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_NOT_ADDED,
                             SSH_CM_ERROR_MEMORY_ALLOC_FAILED,
                             NULL,
                             NULL);
            return 0;
        }

        if (ssh_hash_allocate(SSH_CM_HASH_ALGORITHM, &hash) != SSH_CRYPTO_OK)
        {
            ssh_adt_destroy(cm_crl->revoked);
            cm_crl->revoked = NULL;
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_NOT_ADDED,
                             SSH_CM_ERROR_INSUFFICIENT_RESOURCES,
                             NULL,
                             NULL);
            return 0;
        }
        digest_len = ssh_hash_digest_length(SSH_CM_HASH_ALGORITHM);

        /* Optimization: fetch the ber just once outside the loop */
        if ((issuer_name_der =
             ssh_cm_get_canonical_dn_der(crl->issuer_name,
                                         &issuer_name_der_len)) == NULL)
        {
            ssh_hash_free(hash);
            ssh_adt_destroy(cm_crl->revoked);
            cm_crl->revoked = NULL;
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_NOT_ADDED,
                             SSH_CM_ERROR_INSUFFICIENT_RESOURCES,
                             NULL,
                             NULL);
            return 0;
        }

        /* Now apply this revocation list to all the certificates on our
           local cache, and add entry to mapping of all revoked serial
           numbers. */
        for (revoked = crl->revoked; revoked; revoked = next_revoked)
        {
            unsigned char *buf;
            size_t buf_len;

            /* Processing will remove revoked cert list from CRL, copy
               will remain at ADT mapping above. */
            next_revoked = revoked->next;

            if ((r = ssh_calloc(1, sizeof(*r))) == NULL)
            {
                ssh_free(issuer_name_der);
                ssh_hash_free(hash);
                ssh_adt_destroy(cm_crl->revoked);
                cm_crl->revoked = NULL;
                ssh_cm_error_set(search,
                                 SSH_CM_SSTATE_CERT_NOT_ADDED,
                                 SSH_CM_ERROR_MEMORY_ALLOC_FAILED,
                                 NULL,
                                 NULL);
                return 0;
            }

            ssh_mprz_init_set(&r->serial, &revoked->serial_number);
            ssh_ber_time_set(&r->revocation, &revoked->revocation_date);
            r->reason = revoked->extensions.reason_code;

            /* Insert into set of revoked certificates. */
            ssh_adt_insert(cm_crl->revoked, r);

            /* Make space by getting rid of duplicate data. Don't want
               to free next, unprocessed though. */
            revoked->next = NULL;
            ssh_x509_revoked_free(revoked);

            /* Check revocation date against current time. */
            if (ssh_ber_time_cmp(&r->revocation, &search->cur_time) > 0)
            {
                /* Don't revoke (mark cert as revoked) yet, instead make
                   the needed adjustments to the next check. */
                if (ssh_ber_time_cmp(&r->revocation, &ca->crl_recompute_after)
                    < 0)
                  ssh_ber_time_set(&ca->crl_recompute_after, &r->revocation);
                continue;
            }


            found = NULL;

            /* Heuristically try searching first with the serial number
               and issuer name hash. This might lead to faster
               search. */
            buf = ssh_cm_get_issuer_serial_hash(hash,
                                                &r->serial,
                                                issuer_name_der,
                                                issuer_name_der_len,
                                                digest);
            if (buf)
            {
                if (ssh_certdb_find(cm->db,
                                    SSH_CM_DATA_TYPE_CERTIFICATE,
                                    SSH_CM_KEY_TYPE_SI_HASH,
                                    digest, digest_len,
                                    &found) != SSH_CDBET_OK)
                  found = NULL;
            }
            else
            {
              nomem:
                ssh_free(issuer_name_der);
                ssh_hash_free(hash);
                ssh_adt_destroy(cm_crl->revoked);
                cm_crl->revoked = NULL;
                ssh_cm_error_set(search,
                                 SSH_CM_SSTATE_CERT_NOT_ADDED,
                                 SSH_CM_ERROR_MEMORY_ALLOC_FAILED,
                                 NULL,
                                 NULL);
                return 0;
            }

            if (found == NULL)
            {
                /* Convert the serial number into buffer inplace, then
                   look using serial numbers only. This will append into
                   result, and result into duplicates.  */
                buf_len = (ssh_mprz_get_size(&r->serial, 2) + 7)/8;
                if ((buf = ssh_calloc(1, buf_len)) != NULL)
                {
                    ssh_mprz_get_buf(buf, buf_len, &r->serial);
                    if (ssh_certdb_find(cm->db,
                                        SSH_CM_DATA_TYPE_CERTIFICATE,
                                        SSH_CM_KEY_TYPE_SERIAL_NO,
                                        buf, buf_len,
                                        &found) != SSH_CDBET_OK)
                      found = NULL;
                    ssh_free(buf);
                }
                else
                {
                    goto nomem;
                }
            }

            if (found == NULL)
              continue;

            /* Now we must skip all those certificates that do not match
               our issuers names. At the moment we match to ALL of the
               names of the issuer, and thus this is not perhaps the
               best way. */

            /* Revoke the certificates. */
            for (tmp = found->head; tmp; tmp = tmp->next)
            {
                SshCMCertificate cm_cert = tmp->entry->context;
                SshCertDBKey *issuer_names;

                /* Serial numbers did not match (of course this should
                   not happen if search function is OK) */
                if (ssh_mprz_cmp(
                            &r->serial, &cm_cert->cert->serial_number) != 0)
                  continue;

                /* Has already been revoked! */
                if (!ssh_cm_trust_is_valid(cm_cert, search)
                    && ssh_cm_trust_is_root(cm_cert, search) == false)
                  continue;

                /* Get the issuer names of the certificate. */
                issuer_names = NULL;
                if (ssh_cm_key_set_from_cert(&issuer_names,
                                             SSH_CM_KEY_CLASS_ISSUER,
                                             cm_cert))
                {
                    if (!ssh_cm_key_match(issuer_names, ca->entry->names))
                    {
                        /* Not a match. */
                        ssh_certdb_key_free(issuer_names);
                        continue;
                    }
                    ssh_certdb_key_free(issuer_names);
                }
                else
                  continue;

                /* Revoke this certificate */
                ssh_cm_cert_revoke(search, ca, cm_cert, r);
            }

            /* Free the list. */
            ssh_certdb_entry_list_free_all(cm->db, found);
        }

        /* Don't free it again later. */
        ssh_free(issuer_name_der);
        ssh_hash_free(hash);
        crl->revoked = NULL;
    }


    /* Now check the subject certificate against CRL. NOTE: here we
       assume the subject was indeed issued by ca. */
    {
        SshCMRevokedStruct probe;

        if (!ssh_cm_trust_is_valid(subject, search)
            && ssh_cm_trust_is_root(subject, search) == false)
          goto quitnow;

        ssh_mprz_init_set(&probe.serial, &subject->cert->serial_number);
        probe.hash = 0;

        if ((handle = ssh_adt_get_handle_to_equal(cm_crl->revoked, &probe))
            != SSH_ADT_INVALID)
        {
            r = ssh_adt_get(cm_crl->revoked, handle);
            /* The subject is revoked? */
            if (ssh_ber_time_cmp(&r->revocation, &search->cur_time) > 0)
            {
                /* Don't revoke yet, instead make the needed adjustments
                   to the next check. */
                if (ssh_ber_time_cmp(&r->revocation, &ca->crl_recompute_after)
                    < 0)
                  ssh_ber_time_set(&ca->crl_recompute_after, &r->revocation);

                /* Continue. */
                ssh_mprz_clear(&probe.serial);
                goto quitnow;
            }
            ssh_cm_cert_revoke(search, ca, subject, r);
        }
        ssh_mprz_clear(&probe.serial);
    }
   quitnow:
    return 1;
}

/* Asynchronous verification callbacks. */

typedef struct
{
    SshCMCrl          crl;
    SshCMCertificate  ca;
    SshCMContext      cm;
    SshCMSearchContext *search;
    unsigned int      issuer_id;
    unsigned int      subject_id;
    SshOperationDestructorStruct destructor;
} *SshCMVerifyCrl;

static void cm_crl_verify_async_free(SshCMVerifyCrl v_crl)
{
    ssh_certdb_release_entry(v_crl->cm->db, v_crl->ca->entry);
    ssh_certdb_release_entry(v_crl->cm->db, v_crl->crl->entry);

    memset(v_crl, 0, sizeof(*v_crl));
    ssh_free(v_crl);
}

static void cm_crl_verify_async_destructor(bool aborted, void *context)
{
    SshCMVerifyCrl v_crl = context;

    /* Destructor is only used for freeing the context only in the case
       the operation is aborted. Otherwise the context is freed in the
       completion callback. */
    if (aborted)
      cm_crl_verify_async_free(v_crl);
}

/* Completion callback for asynchronous CRL validation. */

static void
cm_crl_verify_async(SshX509Status status, void *param)
{
    SshCMVerifyCrl v_crl = param;
    SshCMContext    cm = v_crl->cm;
    SshCMSearchContext *search = v_crl->search;

    search->waiting -= 1;
    search->async_completed = true;
    search->async_op = NULL;

    if (status == SSH_X509_OK)
    {
        /* Operation was a success. */
        v_crl->crl->trusted = true;
        search->async_ok   = true;

        /* Discard proved message data for the CRL */
        ssh_free(v_crl->crl->crl->pop.proved_message);
        v_crl->crl->crl->pop.proved_message = NULL;
        v_crl->crl->crl->pop.proved_message_len = 0;
    }
    else
    {
        /* Flag the CRL to be deleted. */
        search->async_ok   = false;
        cm_failure_list_add(search, v_crl->issuer_id, v_crl->subject_id);

        /* Not a valid CRL, please remove. */
        SSH_DEBUG(SSH_D_NETFAULT,
                  ("Reject: "
                   "Invalid signature on CRL validation."));
        ssh_cm_error_set(search,
                         SSH_CM_SSTATE_CRL_INVALID_SIGNATURE,
                         SSH_CM_ERROR_CRL_INVALID_SIGNATURE,
                         v_crl->ca,
                         NULL);
    }

    /* Free the operation context. */
    cm_crl_verify_async_free(v_crl);

    /* Set a timeout for the operation control. */
    search->cm->in_callback++;
    ssh_cm_operation_control(cm);
    search->cm->in_callback--;
}


typedef struct
{
    SshCMCertificate  cert;
    SshCMCertificate  ca;
    SshCMContext      cm;
    SshCMSearchContext *search;
    unsigned int      issuer_id;
    unsigned int      subject_id;
    SshOperationDestructorStruct destructor;
} *SshCMVerifyCert;


static void cm_cert_verify_async_free(SshCMVerifyCert v_cert)
{
    /* Remove references. */
    if (v_cert->ca != NULL)
      ssh_certdb_release_entry(v_cert->cm->db, v_cert->ca->entry);
    ssh_certdb_release_entry(v_cert->cm->db, v_cert->cert->entry);

    /* Free the temporary context. */
    memset(v_cert, 0, sizeof(*v_cert));
    ssh_free(v_cert);
}

static void cm_cert_verify_async_destructor(bool aborted, void *context)
{
    SshCMVerifyCert v_cert = context;

    /* Destructor is only used for freeing the context only in the case
       the operation is aborted. Otherwise the context is freed in the
       completion callback. */
    if (aborted)
      cm_cert_verify_async_free(v_cert);
}

static void cm_cert_verify_async(SshX509Status status, void *param)
{
    SshCMVerifyCert v_cert = param;
    SshCMContext   cm = v_cert->cm;
    SshCMSearchContext *search = v_cert->search;

    search->waiting -= 1;
    search->async_completed = true;
    search->async_op = NULL;

    if (status == SSH_X509_OK)
    {
        /* Operation was a success. */
        ssh_cm_trust_mark_signature_ok(v_cert->cert, v_cert->ca, search);
        search->async_ok   = true;

        if (v_cert->cert->self_issued && v_cert->ca == NULL)
          v_cert->cert->self_signed = 1;
    }
    else
    {
        SSH_DEBUG(SSH_D_NETFAULT,
                  ("Reject: "
                   "Invalid signature on certificate validation."));
        ssh_cm_error_set(search,
                         SSH_CM_SSTATE_CERT_INVALID_SIGNATURE,
                         SSH_CM_ERROR_CERT_INVALID_SIGNATURE,
                         v_cert->cert,
                         NULL);

        search->async_ok   = false;
        cm_failure_list_add(search, v_cert->issuer_id, v_cert->subject_id);
    }

    /* Free context. */
    cm_cert_verify_async_free(v_cert);

    /* Set a timeout for the operation control.
     */
    search->cm->in_callback++;
    ssh_cm_operation_control(cm);
    search->cm->in_callback--;
}

#ifdef DEBUG_LIGHT
static void
cm_cert_db_entry_list_print(SshCertDBEntryList *list)
{
    SshCertDBEntryListNode entry;

    for (entry = list->head; entry; entry = entry->next)
    {
        if (entry->entry->tag == SSH_CM_DATA_TYPE_CRL)
        {
            SshCMCrl crl  = entry->entry->context;
            SSH_DEBUG(SSH_D_MIDOK, ("%@",
                                    ssh_cm_render_crl, crl->crl));
        }
        else if (entry->entry->tag == SSH_CM_DATA_TYPE_CERTIFICATE)
        {
            SshCMCertificate cert = entry->entry->context;
            SSH_DEBUG(SSH_D_MIDOK, ("%@",
                                    ssh_cm_render_certificate, cert->cert));
        }
    }
}
#endif /* DEBUG_LIGHT */


/* Apply CRLs at 'list' to subject certificate. */
static bool
cm_crl_apply_internal(
        SshCMSearchContext *search,
        SshCMCertificate    ca,
        SshCMCertificate    subject,
        SshCertDBEntryList *list,
        SshCMStatus *status_p)
{
    SshCertDBEntryListNode entry, next;
    SshCMContext cm = search->cm;
    SshCMCrl cm_crl;
    SshX509ReasonFlags reasons = 0;
    int rv;

    SSH_DEBUG(SSH_D_MIDSTART,
              ("CRL applying to the local database."));

    if (list == NULL)
    {
        *status_p = SSH_CM_STATUS_FAILURE;
        return false;
    }

    if (cm->db == NULL)
    {
        *status_p = SSH_CM_STATUS_FAILURE;
        return false;
    }

    ssh_cm_crl_initial_cert_transform(search, ca, subject);

    cm_crl = NULL;
    /* Find the latest of the CRL's.
       This should be sped up with some actual computations.
       Also those CRL's which have been found to be old could as well be
       thrown out. */
    for (entry = list->head; entry; entry = next)
    {
        next = entry->next;

        if (entry->entry->tag == SSH_CM_DATA_TYPE_CRL)
        {
            SshBerTimeStruct refetch_time;

            cm_crl = entry->entry->context;

            /* Check whether this CRL has been already checked and found
               to be invalid (or expired). */
            if (cm_crl->status_flags & SSH_CM_CRL_FLAG_SKIP)
            {
                if (cm_failure_list_member(search,
                                           ssh_cm_cert_get_cache_id(ca),
                                           ssh_cm_crl_get_cache_id(cm_crl))
                    == false)
                {
                    cm_failure_list_add(search,
                                        ssh_cm_cert_get_cache_id(ca),
                                        ssh_cm_crl_get_cache_id(cm_crl));
                }
                continue;
            }

            /* Check the signature algorithm validity */
            if (ssh_cm_cert_check_signature_algorithm(
                                      cm->config,
                                      cm_crl->crl->pop.signature.pk_algorithm)
                == false)
            {
                cm_crl->status_flags |= SSH_CM_CRL_FLAG_SKIP;
                if (cm_failure_list_member(search,
                                           ssh_cm_cert_get_cache_id(ca),
                                           ssh_cm_crl_get_cache_id(cm_crl))
                    == false)
                {
                    cm_failure_list_add(search,
                                        ssh_cm_cert_get_cache_id(ca),
                                        ssh_cm_crl_get_cache_id(cm_crl));
                }
                SSH_DEBUG(
                        SSH_D_MIDOK, ("Signature algorithm is not allowed."));
                ssh_cm_error_set(search,
                                 SSH_CM_SSTATE_ALGORITHM_NOT_ALLOWED,
                                 SSH_CM_ERROR_CRL_ALGORITHM_STRENGTH_TOO_WEAK,
                                 ca,
                                 NULL);
                continue;
            }

            /* Must not be older that max_crl_validity_secs */
            if (cm->config->max_crl_validity_secs)
            {
                ssh_ber_time_set(&refetch_time, &cm_crl->fetch_time);
                ssh_ber_time_add_secs(&refetch_time,
                                      cm->config->max_crl_validity_secs);
                if (ssh_ber_time_cmp(&refetch_time, &search->cur_time) < 0)
                {
                    SSH_DEBUG(SSH_D_MIDOK, ("Too old; max_crl_validity_secs"));
                    goto too_old;
                }
            }

            /* Next update has to be later than the time searched. */
            if (ssh_ber_time_available(&cm_crl->crl->next_update) &&
                ssh_ber_time_cmp(&cm_crl->crl->next_update,
                                 &search->cur_time) < 0)
            {
                SSH_DEBUG(SSH_D_MIDOK, ("Too old; next_update"));

              too_old:
                /* Remove the CRL, too old for us. */
                cm_crl->status_flags |= SSH_CM_CRL_FLAG_SKIP;

                if (cm_failure_list_member(search,
                                           ssh_cm_cert_get_cache_id(ca),
                                           ssh_cm_crl_get_cache_id(cm_crl))
                    == false)
                {
                    cm_failure_list_add(search,
                                        ssh_cm_cert_get_cache_id(ca),
                                        ssh_cm_crl_get_cache_id(cm_crl));
                }
                ssh_cm_error_set(search,
                                 SSH_CM_SSTATE_CRL_OLD,
                                 SSH_CM_ERROR_CRL_OLD,
                                 ca,
                                 subject);
                continue;
            }

            /* Check whether is trusted or not. */
            if (cm_crl->trusted == false)
            {
                SshCMVerifyCrl v_crl;
                unsigned int iid, sid;

                iid = ssh_cm_cert_get_cache_id(ca);
                sid = ssh_cm_crl_get_cache_id(cm_crl);
                if (cm_failure_list_member(search, iid, sid))
                {
                    ssh_cm_error_set(search,
                                     SSH_CM_SSTATE_CRL_INVALID,
                                     SSH_CM_ERROR_CRL_INVALID,
                                     ca,
                                     subject);

                    *status_p = SSH_CM_STATUS_FAILURE;
                    return false;
                }

                /* Build a verification context, with appropriately
                   referenced CA and CRL. */
                v_crl = ssh_calloc(1, sizeof(*v_crl));
                if (v_crl == NULL)
                {
                    ssh_cm_error_set(search,
                                     SSH_CM_SSTATE_CRL_INVALID,
                                     SSH_CM_ERROR_MEMORY_ALLOC_FAILED,
                                     NULL,
                                     NULL);
                    if (cm_failure_list_member(search,
                                               ssh_cm_cert_get_cache_id(ca),
                                               ssh_cm_crl_get_cache_id(cm_crl))
                        == false)
                    {
                        cm_failure_list_add(search,
                                            ssh_cm_cert_get_cache_id(ca),
                                            ssh_cm_crl_get_cache_id(cm_crl));
                    }

                    *status_p = SSH_CM_STATUS_FAILURE;
                    return false;
                }

                v_crl->crl = cm_crl;
                v_crl->ca  = ca;
                v_crl->cm  = cm;
                v_crl->search = search;
                v_crl->issuer_id = iid;
                v_crl->subject_id = sid;

                /* Clean the async parameters. */
                search->async_completed = false;
                search->async_ok        = false;

                /* Take CRL and CA references. */
                ssh_certdb_take_reference(ca->entry);
                ssh_certdb_take_reference(cm_crl->entry);

                /* Start the asynchronous verification. We will not
                   support aborting of this operation. This means that
                   the time control cannot kill asynchronous
                   verification operation, even if it takes a long
                   time. This is reasonable, as if the asynchronous
                   operation is progressing we can hope that the
                   underlying library timeouts if the method for
                   verification is e.g. removed. */

                /* This arranges v_crl to be freed. */
                search->waiting += 1;
                SSH_ASSERT(search->async_op == NULL);
                search->async_op =
                  ssh_x509_crl_verify_async(cm_crl->crl,
                                            ca->cert->subject_pkey.public_key,
                                            cm_crl_verify_async,
                                            v_crl);

                if (!search->async_completed)
                {
                    ssh_operation_attach_destructor_no_alloc
                      (&v_crl->destructor,
                       search->async_op,
                       cm_crl_verify_async_destructor,
                       v_crl);
                    SSH_DEBUG(SSH_D_MIDOK, ("CRL verification running..."));

                    *status_p = SSH_CM_STATUS_SEARCHING;
                    return true;
                }

                if (!search->async_ok)
                {
                    /* The async codes has set the crl into failure_list
                       already so no need for us to do that. */
                    continue;
                }
            }

            /* Work through the CRL. At this point the CRL has been
               validated against the issuer.  */
            rv = cm_crl_revoke(search, cm_crl, ca, subject, &reasons);
            if (rv == 0)
            {
                cm_crl->status_flags |= SSH_CM_CRL_FLAG_SKIP;

                /* Not a valid CRL, please remove. */
                ssh_cm_error_set(search,
                                 SSH_CM_SSTATE_CRL_INVALID,
                                 SSH_CM_ERROR_CRL_INVALID,
                                 ca,
                                 subject);

                if (cm_failure_list_member(
                            search, ssh_cm_cert_get_cache_id(ca),
                            ssh_cm_crl_get_cache_id(cm_crl))
                    == false)
                {
                    cm_failure_list_add(search,
                                        ssh_cm_cert_get_cache_id(ca),
                                        ssh_cm_crl_get_cache_id(cm_crl));
                }
            }
        }
    }

    /* Check the reasons. */
    if (reasons == 0x80ff)
    {
        /* Now checked against CRL. */
        subject->not_checked_against_crl = false;

        *status_p = SSH_CM_STATUS_OK;
        return true;
    }

    /* Reason codes were not all available, cannot let this go. */
    ssh_cm_error_set(search,
                     SSH_CM_SSTATE_CRL_INVALID,
                     SSH_CM_ERROR_CRL_INVALID,
                     ca,
                     subject);

    *status_p = SSH_CM_STATUS_FAILURE;
    return false;
}

static bool
cm_crl_apply(
        SshCMSearchContext *search,
        SshCMCertificate ca,
        SshCMCertificate subject,
        SshCertDBKey *keys,
        SshCertDBEntryList *crl_list,
        SshCMStatus *status_p)
{
    SshCertDBEntryList *cert_list;
    SshCMContext cm = search->cm;
    bool ok;

    /* Apply this CRL. This validates the CRL, so it might be asynchronous. */
    ok = cm_crl_apply_internal(search, ca, subject, crl_list, status_p);
    if (ok == true)
    {
        SSH_DEBUG(SSH_D_HIGHOK, ("CRL applied."));
        return true;
    }

    /* CRL apply with given CA failed. Now check if we have other,
       certificates with the same subject. Also, the found
       certificates either must have been issued by current CA
       (e.g. are certificate issuers or CA key renewals), or they must
       be issuers of the current CA. */
    cert_list =
        cm_search_local_dbs(
                search,
                SSH_CM_DATA_TYPE_CERTIFICATE,
                keys,
                SSH_CM_SEARCH_RULE_OR);

    if (cert_list != NULL)
    {
        SshCertDBEntryListNode cert_node;
        SshCertDBEntryListNode next_node;

        for (cert_node = cert_list->head;
             cert_node != NULL;
             cert_node = next_node)
        {
            SshCMCertificate ca_other;
            bool found = false;

            ca_other = cert_node->entry->context;
            next_node = cert_node->next;

            if (ssh_cm_cert_get_cache_id(ca_other) !=
                ssh_cm_cert_get_cache_id(ca))
            {
                SshCertDBEntryListNode crl_node;

                for (crl_node = crl_list->head;
                     crl_node;
                     crl_node = crl_node->next)
                {
                    bool failed_member;
                    SshCMCrl crl;

                    crl = crl_node->entry->context;
                    failed_member =
                        cm_failure_list_member(
                                search,
                                ssh_cm_cert_get_cache_id(ca_other),
                                ssh_cm_crl_get_cache_id(crl));
                    if (failed_member == false)
                    {
                        found = true;
                        break;
                    }
                }
            }

            if (found == true)
            {
                SSH_DEBUG(
                        SSH_D_HIGHOK,
                        ("Checking CRL with: %@",
                         ssh_cm_render_certificate, ca_other->cert));

                ssh_certdb_take_reference(ca_other->entry);
                ok =
                    cm_crl_apply_internal(
                            search,
                            ca_other,
                            subject,
                            crl_list,
                            status_p);

                ssh_certdb_release_entry(cm->db, ca_other->entry);

                if (ok == true)
                {
                    ssh_certdb_entry_list_free_all(cm->db, cert_list);

                    SSH_DEBUG(
                            SSH_D_HIGHOK,
                            ("CRL applied with other certificate."));

                    return true;
                }
            }
        }

        SSH_DEBUG(SSH_D_NETFAULT, ("CRL apply failed directly."));
        ssh_certdb_entry_list_free_all(cm->db, cert_list);
    }

    return false;
}

/* Find CRL from the local databases and apply it back to local database. */
static bool
cm_crl_find_and_apply_local_dbs(
        SshCMSearchContext *search,
        SshCMCertificate ca,
        SshCMCertificate subject,
        SshCertDBKey *keys,
        SshCMStatus *status_p)
{
    SshCertDBEntryList *crl_list;
    SshCMContext cm = search->cm;
    bool ok = false;

    /* Look up CRL from the local database. */
    crl_list =
        cm_search_local_dbs(
                search,
                SSH_CM_DATA_TYPE_CRL,
                keys,
                SSH_CM_SEARCH_RULE_OR);

    if (crl_list != NULL)
    {
        /* Validate CRL by applying it back to local database. */
        ok = cm_crl_apply(search, ca, subject, keys, crl_list, status_p);

        ssh_certdb_entry_list_free_all(cm->db, crl_list);
    }
    else
    {
        *status_p = SSH_CM_STATUS_NOT_FOUND;
    }

    return ok;
}

/* Find CRL from the external databases and apply it to local database. */
static void
cm_crl_find_and_apply_external_dbs(
        SshCMSearchContext *search,
        SshCMCertificate ca,
        SshCMCertificate subject,
        SshCertDBKey *keys,
        SshCMStatus *status_p)
{
    SshCMSearchConstraints constraints = search->end_cert;
    SshCertDBEntryList *crl_list = NULL;
    SshCMContext cm = search->cm;
    bool found = false;

    /* Check if we are allowed to look from external databases. */
    if (constraints->local.crl == false)
    {
        *status_p =
            cm_search_dbs(
                    search,
                    SSH_CM_DATA_TYPE_CRL,
                    keys,
                    SSH_CM_SEARCH_RULE_OR,
                    &crl_list);

        switch (*status_p)
        {
        case SSH_CM_STATUS_OK:

            /* Rare but possible situation, found it synchronously. */
            found = true;
            break;

        case SSH_CM_STATUS_SEARCHING:

            /* Searching started and CRL is not available yet. */
            break;

        case SSH_CM_STATUS_NOT_FOUND:
        default:

            ssh_cm_error_set(
                    search,
                    SSH_CM_SSTATE_CRL_NOT_FOUND,
                    SSH_CM_ERROR_CRL_NOT_FOUND,
                    subject,
                    NULL);
            break;
        }
    }
    else
    {
        ssh_cm_error_set(
                search,
                SSH_CM_SSTATE_CRL_NOT_FOUND,
                SSH_CM_ERROR_CRL_NOT_FOUND,
                subject,
                NULL);

        *status_p = SSH_CM_STATUS_NOT_FOUND;
    }

    if (found == true)
    {
        /* Validate CRL by applying it to local database.
           Possible error is returned via status_p to the caller and
           therefore return value can be ignored. */
        (void) cm_crl_apply(search, ca, subject, keys, crl_list, status_p);
    }

    if (crl_list != NULL)
    {
        ssh_certdb_entry_list_free_all(cm->db, crl_list);
    }
}

static SshCMStatus
cm_crl_find_and_apply(
        SshCMSearchContext *search,
        SshCMCertificate ca,
        SshCMCertificate subject,
        SshCertDBKey *keys)
{
    SshCMStatus rv;
    bool ok;

    SSH_DEBUG(
            SSH_D_HIGHSTART,
            ("CMI: Find and apply CRL with CA: %@ and subject %@",
             ssh_cm_render_certificate, ca->cert,
             ssh_cm_render_certificate, subject->cert));

    /* Look up CRL from the local databases. */
    ok = cm_crl_find_and_apply_local_dbs(search, ca, subject, keys, &rv);
    if (ok == false)
    {
        /* Look up CRL form the external databases. */
        cm_crl_find_and_apply_external_dbs(search, ca, subject, keys, &rv);
    }

    return rv;
}

static bool
cm_crl_search(SshCMSearchContext *search,
              SshCMCertificate ca,
              SshCMCertificate subject,
              SshCertDBKey *existing_keys,
              SshCMStatus *status_p)
{
    SshCertDBKey *key = NULL;
    SshCertDBKey *cdpkey = NULL;
    SshX509ExtCRLDistPoints cdps = NULL;
    bool critical;
    bool cdp_available;
    bool found = false;

    SSH_DEBUG(SSH_D_MIDOK, ("Searching for a CRL."));

    /* Check if the subject has an explicit distribution
       point mentioned. That will be used if available. */
    cdp_available =
      ssh_x509_cert_get_crl_dist_points(subject->cert, &cdps, &critical);
    if (cdp_available == true)
    {
        SSH_DEBUG(SSH_D_HIGHSTART, ("CDP is available."));

        for (; cdps; cdps = cdps->next)
        {
            /* Build up a name for searching. */
            bool free_full_name = false;
            SshX509Name full_name;

            if (cdps->full_name)
            {
                full_name = cdps->full_name;
            }
            else if (cdps->dn_relative_to_issuer)
            {
                full_name =
                  cm_dp_make_full_name(subject->cert->issuer_name,
                                       cdps->dn_relative_to_issuer);
                free_full_name = true;
            }
            else
            {
                full_name = NULL;
            }
            if (full_name)
            {
                ssh_cm_key_convert_from_x509_name(&cdpkey, full_name, true);
                if (free_full_name)
                  ssh_x509_name_free(full_name);
            }
        }
    }

    if (existing_keys != NULL)
    {
        SSH_DEBUG(SSH_D_HIGHSTART,
                  ("CMI: Looking for CRL by the issuer name"));
        ssh_cm_key_push_keys(&key, existing_keys);
        /* Make sure the CDP is pushed last, so it will
           get searched first. */
        ssh_cm_key_push_keys(&key, cdpkey);
        ssh_certdb_key_free(cdpkey);
    }
    else
    {
        key = cdpkey;
    }

    *status_p = cm_crl_find_and_apply(search, ca, subject, key);
    if (*status_p == SSH_CM_STATUS_OK)
    {
        found = true;
    }

    ssh_certdb_key_free(key);
    return found;
}

#ifdef SSHDIST_VALIDATOR_OCSP
static bool
cm_ocsp_check(SshCMSearchContext *search,
              SshCMCertificate ca,
              SshCMCertificate subject,
              bool end_entity,
              SshCMStatus *status_p)
{
    SshCMSearchConstraints constraints = search->end_cert;
    SshCMOcspMode ocsp_mode = constraints->ocsp_mode;

    /* Check also whether OCSP is used at all. */
    if (ocsp_mode != SSH_CM_OCSP_NO_OCSP &&
        !(end_entity && ocsp_mode == SSH_CM_OCSP_NO_END_ENTITY_OCSP))
    {
        /* Check the certificate status using OCSP. */
        if (constraints->local.crl == false)
        {
            switch (ssh_cm_ocsp_check_status(search, subject, ca))
            {
              case SSH_CM_STATUS_SEARCHING:
                SSH_DEBUG(SSH_D_HIGHOK,
                          ("Searching from an OCSP server."));

                *status_p = SSH_CM_STATUS_SEARCHING;
                return true;

              default:
                SSH_DEBUG(SSH_D_NETFAULT,
                          ("OCSP based validation did not succeed, "
                           "attempting other means."));

                /* Set OCSP check failed variable in order that
                   proper error can generated if CRL check fails
                   later. */
                search->ocsp_check_failed = true;

                /* Check if allowed to continue. */
                if (ocsp_mode != SSH_CM_OCSP_CRL_AFTER_OCSP)
                {
                    *status_p = SSH_CM_STATUS_NOT_FOUND;
                    return true;
                }
                break;
            }
        }
    }
    else
    {
        SSH_DEBUG(SSH_D_MIDOK,
                  ("No OCSP check for: %@",
                   ssh_cm_render_certificate, subject->cert));
    }

    if (ocsp_mode == SSH_CM_OCSP_OCSP_ONLY)
    {
        SSH_DEBUG(SSH_D_MIDOK,
                  ("No CRL check for: %@ (ocsp-only)",
                   ssh_cm_render_certificate,
                   subject->cert));
        *status_p = SSH_CM_STATUS_NOT_FOUND;
        return true;
    }

    *status_p = SSH_CM_STATUS_OK;
    return false;
}
#endif /* SSHDIST_VALIDATOR_OCSP */

static void ssh_cm_cert_list_clean_key_flags(SshCertDBEntryList *list)
{
    SshCertDBEntryListNode node;
    SshCertDBKey *key;

    for (node = list->head; node; node = node->next)
      for (key = node->entry->names; key; key = key->next)
        ;
}

/* Internal values for state of certificate revocation checking. */
#define SSH_CM_REVOCATION_NOT_CHECKED      0x0 /* Revocation not checked */
#define SSH_CM_REVOCATION_NO_CHECK_NEEDED  0x1 /* No check needed */
#define SSH_CM_REVOCATION_CHECKED_CRL      0x2 /* Checked from CRL */
#define SSH_CM_REVOCATION_CHECKED_OCSP     0x4 /* Checked via OCSP */

/* Routine which verifies the path from ca to end certificate. */
static SshCMStatus
ssh_cm_verify_path(SshCMSearchContext *search,
                   SshCertDBEntryList *chosen)
{
    SshCertDBEntryListNode tmp, prev, pprev;
    SshCMContext cm = search->cm;
    SshCMCertificate ca_cert, subject_cert, crl_signer = NULL;
    SshBerTimeStruct not_before, not_after, cert_not_before, cert_not_after;
    bool critical;
    size_t path_length;
    SshX509CertExtType ext_type;
    uint8_t subject_check_revocation;
    bool search_check_revocation;

    uint32_t policy_mapping, explicit_policy;
    uint32_t inhibit_policy_mapping;
    uint32_t inhibit_any_policy;

    SshCMPolicyTree valid_policy_tree;
    uint32_t depth, level;

    SshCMSearchConstraints constraints = search->end_cert;

    SSH_DEBUG(SSH_D_HIGHSTART, ("CMI: Path validation in process. (%p)",
                                search));

    SSH_ASSERT(constraints != NULL);

    /* Before each verify path operation we need to clean up the flags
       of the keys. This makes the searching from different databases
       work. */
    ssh_cm_cert_list_clean_key_flags(chosen);

    valid_policy_tree = ssh_cm_ptree_alloc();
    if (valid_policy_tree == NULL)
    {
        SSH_DEBUG(SSH_D_NETFAULT, ("Reject: Out of memory"));
        ssh_cm_error_set(search,
                         SSH_CM_SSTATE_CERT_NOT_ADDED,
                         SSH_CM_ERROR_MEMORY_ALLOC_FAILED,
                         NULL,
                         NULL);
        return SSH_CM_STATUS_FAILURE;
    }

    /* Retry this function again. Useful when applied the CRL before. */
   retry:

    path_length = cm->config->max_path_length;
    ssh_ber_time_zero(&not_before);
    ssh_ber_time_zero(&not_after);

    subject_cert = ca_cert = NULL;

    if (!constraints->check_revocation)
      search_check_revocation = false;
    else
      search_check_revocation = true;

    /* Count */
    for (tmp = chosen->head, depth = 0; tmp; tmp = tmp->next, depth++);

    policy_mapping = constraints->policy_mapping;
    if (constraints->explicit_policy)
      explicit_policy = 0;
    else
      explicit_policy = depth + 1;

    if (constraints->inhibit_any_policy)
      inhibit_any_policy = 0;
    else
      inhibit_any_policy = depth + 1;

    inhibit_policy_mapping = constraints->inhibit_policy_mapping;
    if (constraints->inhibit_policy_mapping)
      policy_mapping = 0;
    else
      policy_mapping = depth + 1;

#ifdef DEBUG_LIGHT
    cm_cert_db_entry_list_print(chosen);
#endif /* DEBUG_LIGHT */

    /* Run through all the certificates. */
    for (tmp = chosen->head, pprev = prev = NULL, level = 0;
         tmp;
         pprev = prev, prev = tmp, tmp = tmp->next, level++)
    {
        bool end_entity = false;

        subject_check_revocation = SSH_CM_REVOCATION_NOT_CHECKED;

        /* Path == 0 means that only a end user is allowed after the
           given issuer. */
        if (path_length == (size_t)-1)
        {
            SSH_DEBUG(SSH_D_NETFAULT, ("Reject: "
                                       "Path length was exceeded."));
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_PATH_LENGTH_REACHED,
                             SSH_CM_ERROR_PATH_LENGTH_REACHED,
                             NULL,
                             NULL);
            ssh_cm_ptree_free(valid_policy_tree);
            return SSH_CM_STATUS_NOT_VALID;
        }

        if (tmp->entry == NULL ||
            tmp->entry->tag != SSH_CM_DATA_TYPE_CERTIFICATE)
          ssh_fatal(
                  "error: certificate cache contains corrupted certificates.");

        /* Take the CM certificate. */
        subject_cert = tmp->entry->context;

        /* Keep the acting CA department updated. */
        if (prev)
          ca_cert = prev->entry->context;
        else
          ca_cert = NULL;

        crl_signer = NULL;

        if (tmp->next)
          subject_cert->acting_ca = true;
        else
          end_entity = true;

        if (ca_cert)
        {
            size_t cert_path_length;
            bool ca;

            if (!ssh_x509_cert_get_basic_constraints(ca_cert->cert,
                                                     &cert_path_length,
                                                     &ca,
                                                     &critical))
              ca = false;

            if (pprev &&
                (ca_cert->self_issued && !ca_cert->self_signed) &&
                !ca)
            {
                /* If we have issued-to-self certificate that is not a
                   CA in the middle of the path, consider is as a CRL
                   issuer. */
                crl_signer = ca_cert;
                ca_cert = pprev->entry->context;
            }
            else
            {
                if (!ca)
                {
                    SSH_DEBUG(SSH_D_NETFAULT,
                              ("Reject: "
                               "Acting CA is missing basicConstraints/CA"));

                    ssh_cm_error_set(search,
                                     SSH_CM_SSTATE_CERT_CA_INVALID,
                                     SSH_CM_ERROR_CERT_CA_INVALID,
                                     ca_cert,
                                     NULL);
                    ssh_cm_ptree_free(valid_policy_tree);
                    cm_failure_list_add(
                            search,
                            ssh_cm_cert_get_cache_id(ca_cert),
                            ssh_cm_cert_get_cache_id(subject_cert));
                    return SSH_CM_STATUS_NOT_VALID;
                }
            }
        }

        SSH_DEBUG(SSH_D_MIDOK,
                  ("Considering %s serial: %@",
                   !ca_cert ? "CA" : "UserCertificate or SubCA",
                   ssh_cm_render_mp, &subject_cert->cert->serial_number));

        /* First and foremost check that the certificate isn't yet
           revoked. This information is scanned in the search phase too, so
           we might as well skip this. However, for now lets be on the safe
           side. */
        if (!ssh_cm_trust_is_valid(subject_cert, search) &&
            ssh_cm_trust_is_root(subject_cert, search) != true &&
            subject_cert->status == SSH_CM_VS_REVOKED)
        {
            SSH_DEBUG(SSH_D_NETFAULT,
                      ("Reject: "
                       "A revoked certificate encountered."));
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_REVOKED,
                             SSH_CM_ERROR_CERT_REVOKED,
                             subject_cert,
                             NULL);
            ssh_cm_ptree_free(valid_policy_tree);
            return SSH_CM_STATUS_NOT_VALID;
        }

        if (!ssh_cm_trust_is_valid(subject_cert, search) &&
            ssh_cm_trust_is_root(subject_cert, search) != true &&
            subject_cert->status == SSH_CM_VS_HOLD)
        {
            SSH_DEBUG(SSH_D_NETFAULT,
                      ("Reject: "
                       "A suspended certificate encountered."));
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_REVOKED,
                             SSH_CM_ERROR_CERT_SUSPENDED,
                             subject_cert,
                             NULL);

            /* When certificate is marked with HOLD, it's crl_recompute_after
               it set from the ca that suspended it. Recheck hold status
               regularly to ensure timely reactivation. */
            SSH_DEBUG(
                    SSH_D_MIDOK,
                    ("Next CRL recomputation at '%@'.",
                     ssh_ber_time_render, &subject_cert->crl_recompute_after));

            if (ssh_ber_time_cmp(&subject_cert->crl_recompute_after,
                                 &search->cur_time) < 0)
              subject_cert->not_checked_against_crl = true;
        }

        /* Now we can try something more computational. */

        /* Check the signature, if not already checked. */
        if (!ssh_cm_trust_is_root(subject_cert, search))
        {
            /* Get the previous certificate (e.g. issuer for this). */
            if (prev)
            {
                unsigned int iid, sid;
                bool already_failed = false;

                iid = ssh_cm_cert_get_cache_id(ca_cert);
                sid = ssh_cm_cert_get_cache_id(subject_cert);

                /* Check signature unless check has already failed for
                   this search and subject is not not trusted or issuer
                   of trust does not match the current CA. */
                already_failed = cm_failure_list_member(search, iid, sid);

                if (!already_failed
                    && (!ssh_cm_trust_in_signature_predicate(subject_cert,
                                                             search)
                        || subject_cert->trusted.trusted_issuer_id
                        != ca_cert->entry->id))
                {
                    SshCMVerifyCert v_cert = ssh_calloc(1, sizeof(*v_cert));

                    if (v_cert)
                    {
                        v_cert->cert = subject_cert;
                        v_cert->ca   = ca_cert;
                        v_cert->cm   = cm;
                        v_cert->search = search;
                        v_cert->issuer_id = iid;
                        v_cert->subject_id = sid;

                        /* Async set up. */
                        search->async_completed = false;
                        search->async_ok        = false;

                        /* Reference both parties. */
                        ssh_certdb_take_reference(ca_cert->entry);
                        ssh_certdb_take_reference(subject_cert->entry);

                        /* Start the asynchronous operation. */
                        search->waiting += 1;
                        SSH_ASSERT(search->async_op == NULL);
                        search->async_op =
                          ssh_x509_cert_verify_async(subject_cert->cert,
                                                     ca_cert->cert->
                                                     subject_pkey.public_key,
                                                     cm_cert_verify_async,
                                                     v_cert);

                        if (!search->async_completed)
                        {
                            ssh_operation_attach_destructor_no_alloc
                              (&v_cert->destructor,
                               search->async_op,
                               cm_cert_verify_async_destructor,
                               v_cert);

                            SSH_DEBUG(
                                    SSH_D_LOWOK, ("Verifying asynchronously"));
                            ssh_cm_ptree_free(valid_policy_tree);
                            return SSH_CM_STATUS_SEARCHING;
                        }

                        if (!search->async_ok)
                        {
                            ssh_cm_ptree_free(valid_policy_tree);
                            return SSH_CM_STATUS_NOT_VALID;
                        }
                    }
                    else
                    {
                        SSH_DEBUG(SSH_D_NETFAULT,
                                  ("Reject: "
                                   "No space for certificate validation."));
                        ssh_cm_error_set(search,
                                         SSH_CM_SSTATE_CERT_NOT_ADDED,
                                         SSH_CM_ERROR_MEMORY_ALLOC_FAILED,
                                         NULL,
                                         NULL);
                        ssh_cm_ptree_free(valid_policy_tree);
                        return SSH_CM_STATUS_FAILURE;
                    }
                }
            }
            else
            {
                /* Check first that the certificate actually is or
                   has been valid. */
                if (!ssh_cm_trust_check(subject_cert, NULL, search))
                {
                    SSH_DEBUG(SSH_D_NETFAULT, ("Reject: "
                                  "Certificate is not trusted currently."));
                    ssh_cm_error_set(search,
                                     SSH_CM_SSTATE_CERT_CA_INVALID,
                                     SSH_CM_ERROR_CERT_CA_INVALID,
                                     ca_cert,
                                     NULL);
                    ssh_cm_ptree_free(valid_policy_tree);
                    return SSH_CM_STATUS_NOT_VALID;
                }
            }

            /* Check that the certificates signature is valid. */
            if (subject_cert->trusted.trusted_signature == false)
            {
                /* We cannot continue without valid signature. */
                SSH_DEBUG(SSH_D_NETFAULT, ("Reject: " "Invalid signature."));
                ssh_cm_error_set(search,
                                 SSH_CM_SSTATE_CERT_INVALID_SIGNATURE,
                                 SSH_CM_ERROR_CERT_INVALID_SIGNATURE,
                                 subject_cert,
                                 NULL);
                ssh_cm_ptree_free(valid_policy_tree);
                return SSH_CM_STATUS_NOT_VALID;
            }
        }
        else
        {
            if (ssh_cm_trust_in_signature_predicate(subject_cert,
                                                    search) == false &&
                subject_cert->self_issued)
            {
                SshCMVerifyCert v_cert = ssh_calloc(1, sizeof(*v_cert));

                if (v_cert)
                {
                    v_cert->cert = subject_cert;
                    v_cert->ca   = NULL;
                    v_cert->cm   = cm;
                    v_cert->search = search;

                    /* Async set up. */
                    search->async_completed = false;
                    search->async_ok        = false;

                    /* Reference both parties. */
                    ssh_certdb_take_reference(subject_cert->entry);

                    /* Start the asynchronous operation. */
                    search->waiting += 1;
                    SSH_ASSERT(search->async_op == NULL);
                    search->async_op =
                      ssh_x509_cert_verify_async(subject_cert->cert,
                                                 subject_cert->cert->
                                                 subject_pkey.public_key,
                                                 cm_cert_verify_async,
                                                 v_cert);

                    if (!search->async_completed)
                    {
                        ssh_operation_attach_destructor_no_alloc
                          (&v_cert->destructor,
                           search->async_op,
                           cm_cert_verify_async_destructor,
                           v_cert);

                        SSH_DEBUG(SSH_D_LOWOK, ("Verifying asynchronously"));
                        ssh_cm_ptree_free(valid_policy_tree);
                        return SSH_CM_STATUS_SEARCHING;
                    }

                    if (!search->async_ok)
                    {
                        ssh_cm_ptree_free(valid_policy_tree);
                        return SSH_CM_STATUS_NOT_VALID;
                    }
                }
                else
                {
                    SSH_DEBUG(SSH_D_NETFAULT,
                              ("Reject: "
                               "No space for certificate validation."));
                    ssh_cm_error_set(search,
                                     SSH_CM_SSTATE_CERT_NOT_ADDED,
                                     SSH_CM_ERROR_MEMORY_ALLOC_FAILED,
                                     NULL,
                                     NULL);
                    ssh_cm_ptree_free(valid_policy_tree);
                    return SSH_CM_STATUS_FAILURE;
                }
            }
            else
            {
                /* This is done only for non-selfsigned roots. */
                ssh_cm_trust_mark_signature_ok(subject_cert,
                                               subject_cert,
                                               search);
            }
        }

        crl_signer = crl_signer ? crl_signer : ca_cert;

        /* If not an end certificate, and the current one has been
           defined to be a CRL issuer then try to find the actual CRL
           (and apply it). */
        if (crl_signer)
        {
            SSH_ASSERT(subject_check_revocation
                       == SSH_CM_REVOCATION_NOT_CHECKED);

            if ((subject_cert->self_issued && !subject_cert->self_signed) &&
                ssh_cm_trust_is_valid(crl_signer, search))
            {
                SSH_DEBUG(
                        SSH_D_MIDOK,
                        ("Self issued CA key updated SUBCA of trusted issuer. "
                         "Not checking revocation for this cert, as old key "
                         "may no longer issues CRL's"));
                subject_check_revocation |= SSH_CM_REVOCATION_NO_CHECK_NEEDED;
                path_length++;
            }

            /* Test for CRL. */
            if (search_check_revocation &&
                subject_cert->not_checked_against_crl == false &&
                ssh_ber_time_cmp(&crl_signer->crl_recompute_after,
                                 &search->cur_time) > 0)
            {
                /* The revocation information has been verified recently
                   enough, thus we may happily continue to computing the
                   validity times. */
                SSH_DEBUG(SSH_D_MIDOK,
                          ("Certificate %@ has been checked against CRL.",
                           ssh_cm_render_mp,
                           &subject_cert->cert->serial_number));
                SSH_DEBUG(SSH_D_MIDOK,
                          ("CRL not rechecked until '%@'.",
                           ssh_ber_time_render,
                           &crl_signer->crl_recompute_after));
                subject_check_revocation |= SSH_CM_REVOCATION_CHECKED_CRL;
            }

#ifdef SSHDIST_VALIDATOR_OCSP
            /* Test for OCSP. */
            if (search_check_revocation &&
                subject_cert->not_checked_against_crl == false &&
                ssh_ber_time_available(&subject_cert->ocsp_valid_not_after) &&
                ssh_ber_time_cmp(&subject_cert->ocsp_valid_not_after,
                                 &search->cur_time) > 0)
            {
                /* The revocation information has been verified recently
                   enough, thus we may happily continue to computing the
                   validity times. */
                SSH_DEBUG(SSH_D_MIDOK,
                          ("Certificate %@ has been checked against OCSP.",
                           ssh_cm_render_mp,
                           &subject_cert->cert->serial_number));
                SSH_DEBUG(SSH_D_MIDOK,
                          ("OCSP not rechecked until '%@'.",
                           ssh_ber_time_render,
                           &subject_cert->ocsp_valid_not_after));
                subject_check_revocation |= SSH_CM_REVOCATION_CHECKED_OCSP;
            }
#endif /* SSHDIST_VALIDATOR_OCSP */

            if (crl_signer->crl_issuer == false
                || subject_cert->crl_user == false)
            {
                subject_check_revocation |= SSH_CM_REVOCATION_NO_CHECK_NEEDED;
            }

            if (search_check_revocation
                && subject_check_revocation == SSH_CM_REVOCATION_NOT_CHECKED)
            {
                bool crl_found;
                SshCMStatus rv;

#ifdef SSHDIST_VALIDATOR_OCSP
                bool ocsp_done;

                ocsp_done =
                  cm_ocsp_check(search, crl_signer, subject_cert,
                                end_entity, &rv);
                if (ocsp_done == true)
              {
                  ssh_cm_ptree_free(valid_policy_tree);
                  return rv;
              }
#endif /* SSHDIST_VALIDATOR_OCSP */

                /* Search CRL. */
                crl_found =
                  cm_crl_search(search, crl_signer, subject_cert,
                                prev->entry->names, &rv);
                if (crl_found == false)
                {
                    /* Search operation didn't find anything. */
                    if (rv == SSH_CM_STATUS_NOT_FOUND)
                      rv = SSH_CM_STATUS_NOT_VALID;

                    ssh_cm_ptree_free(valid_policy_tree);
                    return rv;
                }

                goto retry;
              } /* if (search_check_revocation) */
          } /* if (crl_signer) */

        if (search_check_revocation &&
            !ssh_cm_trust_is_valid(subject_cert, search))
        {
            /* The certificate status is not yet resolved to OK. We
               cannot trust it as this implies that there is not
               enough revocation data to rigorously prove that it
               has not been revoked. Thus we fail at this point.

               This is the first place where all revocation information
               should be available, as CRLs and possibly OCSP has been
               now checked.
            */
            SSH_DEBUG(SSH_D_NETFAULT,
                      ("Reject: Certificate status is unknown."));
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_INVALID,
                             SSH_CM_ERROR_CERT_INVALID,
                             subject_cert,
                             NULL);
            ssh_cm_ptree_free(valid_policy_tree);
            return SSH_CM_STATUS_NOT_VALID;
        }

        /* Dates */
        ssh_ber_time_zero(&cert_not_before);
        ssh_ber_time_zero(&cert_not_after);

        if (ssh_x509_cert_get_validity(subject_cert->cert,
                                       &cert_not_before,
                                       &cert_not_after) == false)
        {
            SSH_DEBUG(SSH_D_NETFAULT,
                      ("Certificate validity information unavailable."));
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_NOT_IN_INTERVAL,
                             SSH_CM_ERROR_CERT_VALIDITY_PERIOD_NOT_DETERMINED,
                             subject_cert,
                             NULL);

            /* Should really remove this certificate from the
               search, but sadly its too difficult to do... at the
               moment anyway. */
            ssh_cm_ptree_free(valid_policy_tree);
            return SSH_CM_STATUS_NOT_VALID;
        }

        if (!ssh_ber_time_available(&not_before) &&
            !ssh_ber_time_available(&not_after))
        {
            ssh_ber_time_set(&not_before, &cert_not_before);
            ssh_ber_time_set(&not_after,  &cert_not_after);
        }

        /* Compute intersection between the certificate validity times and
           the global times. */
        if (ssh_ber_time_cmp(&not_before, &cert_not_before) < 0)
          ssh_ber_time_set(&not_before, &cert_not_before);
        if (ssh_ber_time_cmp(&not_after, &cert_not_after) > 0)
          ssh_ber_time_set(&not_after, &cert_not_after);

        /* Clip to the searching validity times. */
        if (ssh_ber_time_available(&search->valid_time_start)
            && ssh_ber_time_cmp(&not_before, &search->valid_time_start) < 0)
          ssh_ber_time_set(&not_before, &search->valid_time_start);

        if (ssh_ber_time_available(&search->valid_time_end)
            && ssh_ber_time_cmp(&not_after, &search->valid_time_end) > 0)
          ssh_ber_time_set(&not_after, &search->valid_time_end);

#ifdef SSHDIST_VALIDATOR_OCSP
        /* Apply OCSP time restrictions if available. */
        if (subject_check_revocation & SSH_CM_REVOCATION_CHECKED_OCSP)
        {
            if (ssh_ber_time_available(&subject_cert->ocsp_valid_not_before))
              if (ssh_ber_time_cmp(&not_before,
                                   &subject_cert->ocsp_valid_not_before) < 0)
                ssh_ber_time_set(&not_before,
                                 &subject_cert->ocsp_valid_not_before);
            if (ssh_ber_time_available(&subject_cert->ocsp_valid_not_after))
              if (ssh_ber_time_cmp(&not_after,
                                   &subject_cert->ocsp_valid_not_after) > 0)
                ssh_ber_time_set(&not_after,
                                 &subject_cert->ocsp_valid_not_after);
        }
#endif /* SSHDIST_VALIDATOR_OCSP */

        /* CRL time restriction. */
        if ((subject_check_revocation & SSH_CM_REVOCATION_CHECKED_CRL) &&
            crl_signer &&
            ssh_ber_time_available(&crl_signer->crl_recompute_after) &&
            search_check_revocation == true &&
            subject_cert->crl_user == true)
          if (ssh_ber_time_cmp(&not_after,
                               &crl_signer->crl_recompute_after) > 0)
            ssh_ber_time_set(&not_after,
                             &crl_signer->crl_recompute_after);

        SSH_DEBUG(SSH_D_MIDOK,
                  ("Validity: not before '%@' not after '%@'",
                   ssh_ber_time_render, &not_before,
                   ssh_ber_time_render, &not_after));

        /* Check that the validity times do not cross (e.g. become
           invalid). */
        if (ssh_ber_time_cmp(&not_before, &not_after) > 0)
        {
            SSH_DEBUG(SSH_D_NETFAULT,
                      ("Reject: "
                       "Validity interval impossible."));

            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_INTERVAL_NOT_VALID,
                             SSH_CM_ERROR_INTERVAL_NOT_VALID,
                             subject_cert,
                             NULL);
            ssh_cm_ptree_free(valid_policy_tree);
            return SSH_CM_STATUS_NOT_VALID;
        }

        /* Following code apparently modifies the validity times of the
           CM certificate. */
        ssh_cm_trust_update_validity(subject_cert,
                                     crl_signer,
                                     &not_before, &not_after, search);

        /*******************************************************/
        /* PKIX specific checks */

        /* Policy information, constraints and mapping processing;
           initialize for certificate at current level. */
        if (level > 0)
        {
            if (!ssh_cm_policy_init(subject_cert,
                                    &valid_policy_tree, depth, level,
                                    &policy_mapping, &inhibit_policy_mapping,
                                    &inhibit_any_policy, &explicit_policy))
            {
                ssh_cm_ptree_free(valid_policy_tree);
                return SSH_CM_STATUS_NOT_VALID;
            }
        }

        /* Handle critical extensions. */
        for (ext_type = 0; ext_type < SSH_X509_EXT_MAX; ext_type++)
        {
            /* Check if the extension is available and critical. */
            if (!ssh_x509_cert_ext_available(subject_cert->cert,
                                             ext_type,
                                             &critical))
              continue;

            /* Now handle the extensions. */
            switch (ext_type)
            {
                /* The basic constraints. */
              case SSH_X509_EXT_BASIC_CNST:
              {
                  size_t cert_path_length;
                  bool ca;

                  /* Handle the PKIX certificate parameters. */
                  if (ssh_x509_cert_get_basic_constraints(subject_cert->cert,
                                                          &cert_path_length,
                                                          &ca,
                                                          &critical) == true)
                  {
                      /* Strict check for validity of the CA. */
                      if (subject_cert->acting_ca && ca == false)
                      {
                          SSH_DEBUG(SSH_D_NETFAULT,
                                    ("Reject: "
                                     "Acting CA is not really a CA."));
                          ssh_cm_error_set(search,
                                           SSH_CM_SSTATE_CERT_CA_INVALID,
                                           SSH_CM_ERROR_CERT_CA_INVALID,
                                           ca_cert,
                                           NULL);
                          ssh_cm_ptree_free(valid_policy_tree);
                          return SSH_CM_STATUS_NOT_VALID;
                      }

                      if (cert_path_length != SSH_X509_MAX_PATH_LEN)
                      {
                          cert_path_length++;

                          if (path_length > cert_path_length ||
                              path_length == SSH_X509_MAX_PATH_LEN)
                            path_length = cert_path_length;
                      }
                  }
                  else
                  {
                      SSH_DEBUG(SSH_D_NETFAULT,
                                ("Reject: "
                                 "Basic constraints extension unavailable."));
                      ssh_cm_error_set(search,
                                       SSH_CM_SSTATE_CERT_DECODE_FAILED,
                                       SSH_CM_ERROR_CERT_DECODE_FAILED,
                                       subject_cert,
                                       NULL);
                      ssh_cm_ptree_free(valid_policy_tree);
                      return SSH_CM_STATUS_NOT_VALID;
                  }
              }
                break;

              case SSH_X509_EXT_KEY_USAGE:
              {
                  SshX509UsageFlags flags;

                  if (ssh_x509_cert_get_key_usage(subject_cert->cert,
                                                  &flags, &critical))
                  {
                      if (subject_cert->acting_ca &&
                          flags != 0 &&
                          (flags & SSH_X509_UF_KEY_CERT_SIGN) == 0)
                      {
                          SSH_DEBUG(SSH_D_NETFAULT,
                                    ("Reject: "
                                     "Acting CA is not allowed to sign."));
                          ssh_cm_error_set(search,
                                           SSH_CM_SSTATE_CERT_CA_INVALID,
                                           SSH_CM_ERROR_CERT_CA_INVALID,
                                           subject_cert,
                                           NULL);
                          ssh_cm_ptree_free(valid_policy_tree);
                          return SSH_CM_STATUS_NOT_VALID;
                      }
                  }
                  else
                  {
                      SSH_DEBUG(SSH_D_NETFAULT,
                                ("Reject: "
                                 "Key usage extensions unavailable."));
                      ssh_cm_error_set(search,
                                       SSH_CM_SSTATE_CERT_DECODE_FAILED,
                                       SSH_CM_ERROR_CERT_DECODE_FAILED,
                                       subject_cert,
                                       NULL);
                      ssh_cm_ptree_free(valid_policy_tree);
                      return SSH_CM_STATUS_NOT_VALID;
                  }
              }
                break;

              case SSH_X509_EXT_CERT_POLICIES:
              case SSH_X509_EXT_POLICY_MAPPINGS:
              case SSH_X509_EXT_POLICY_CNST:
              case SSH_X509_EXT_INHIBIT_ANY_POLICY:
                /* Nothing here */
                break;

              case SSH_X509_EXT_NAME_CNST:
                /* Checks need to be written. */

                /* Basically: if either the permitted or excluded
                   subtrees is present then compute the union of the
                   current ones. Then check all the names of the
                   certificates after that they admit these constraints.

                   This implementation may need following subroutines.

                   (a) code to handle the subtree checks (and matching
                   the wildcards)
                   (b) computing the union etc.
                   (c) matching all the name types (which is a bit
                   awful exercise).
                */

                /* For now either let this pass, or return an error. */
                SSH_DEBUG(
                        SSH_D_NETFAULT,
                        ("WARNING: IGNORED: "
                         "permitted and excluded trees (name constraints)."));
                break;

                /* Ignorable extensions. */
              case SSH_X509_EXT_AUTH_KEY_ID:
              case SSH_X509_EXT_SUBJECT_KEY_ID:
              case SSH_X509_EXT_SUBJECT_ALT_NAME:
              case SSH_X509_EXT_ISSUER_ALT_NAME:
              case SSH_X509_EXT_CRL_DIST_POINTS:
              case SSH_X509_EXT_SUBJECT_DIR_ATTR:
              case SSH_X509_EXT_AUTH_INFO_ACCESS:
              case SSH_X509_EXT_EXT_KEY_USAGE:
                break;

              default:
                if (critical)
                {
                    SSH_DEBUG(SSH_D_NETFAULT,
                              ("Reject: "
                               "Unknown critical extension found."));
                    ssh_cm_error_set(
                            search,
                            SSH_CM_SSTATE_CERT_CRITICAL_EXT,
                            SSH_CM_ERROR_CERT_UNSUPPORTED_CRITICAL_EXT,
                            subject_cert,
                            NULL);
                    ssh_cm_ptree_free(valid_policy_tree);
                    return SSH_CM_STATUS_NOT_VALID;
                }
            }
        }

        /* Handle the fixed path length case. E.g. we can override the
           certificate if we want to. Usually we don't.  */
        if (path_length > subject_cert->trusted.path_length &&
            subject_cert->trusted.path_length != (size_t)-1)
          path_length = subject_cert->trusted.path_length;

        /* Update the trust computation date. */
        ssh_cm_trust_computed(subject_cert, search);

        if (ssh_cm_trust_check(subject_cert, ca_cert, search) == false)
        {
            /* Something happened and the certificate is not
               valid. However, we require that all certificates in the
               chain are valid, thus we return an error here. */
            SSH_DEBUG(SSH_D_FAIL,
                      ("Reject: "
                       "Cert was not marked trusted in finalization."));
            ssh_cm_error_set(search,
                             SSH_CM_SSTATE_CERT_INVALID,
                             SSH_CM_ERROR_CERT_INVALID,
                             subject_cert,
                             NULL);
            ssh_cm_ptree_free(valid_policy_tree);
            return SSH_CM_STATUS_NOT_VALID;
        }

        /* Prepare for next certificate */
        if (level > 0)
        {
            if (!ssh_cm_policy_prepare(
                        subject_cert,
                        &valid_policy_tree, depth, level,
                        &policy_mapping, &inhibit_policy_mapping,
                        &inhibit_any_policy,
                        &explicit_policy))
            {
                SSH_DEBUG(SSH_D_FAIL,
                          ("Reject: "
                           "Invalid policy when preparing next certificate"));
                ssh_cm_error_set(search,
                                 SSH_CM_SSTATE_INVALID_POLICY,
                                 SSH_CM_ERROR_INVALID_POLICY,
                                 subject_cert,
                                 NULL);
                ssh_cm_ptree_free(valid_policy_tree);
                return SSH_CM_STATUS_NOT_VALID;
            }
        }

        /* Reduce the path length by one. */
        path_length--;
    }

    if (ssh_cm_policy_wrapup(subject_cert,
                             &valid_policy_tree, depth, level - 1,
                             constraints->user_initial_policy_set,
                             constraints->user_initial_policy_set_size,
                             &policy_mapping, &inhibit_policy_mapping,
                             &inhibit_any_policy,
                             &explicit_policy))
    {
        ssh_cm_ptree_free(valid_policy_tree);
        return SSH_CM_STATUS_OK;
    }
    else
    {
        ssh_cm_error_set(search,
                         SSH_CM_SSTATE_INVALID_POLICY,
                         SSH_CM_ERROR_INVALID_POLICY,
                         subject_cert,
                         NULL);
        ssh_cm_ptree_free(valid_policy_tree);
        return SSH_CM_STATUS_NOT_VALID;
    }
}

/* Simple stack. */
typedef struct SshDStackRec
{
    struct SshDStackRec *next;
    void *data;
} *SshDStack, SshDStackStruct;

static void *ssh_dstack_pop(SshDStack *stack)
{
    void *data;
    SshDStack next;

    if (stack == NULL)
      return NULL;

    if (*stack != NULL)
    {
        data = (*stack)->data;
        next = (*stack)->next;
        ssh_free(*stack);
        *stack = next;
        return data;
    }
    return NULL;
}

static void ssh_dstack_push(SshDStack *stack, void *data)
{
    SshDStack node;

    if (stack == NULL)
      return;

    node = ssh_malloc(sizeof(*node));
    if (node != NULL)
    {
        node->data = data;
        node->next = *stack;
        *stack = node;
    }
}

static bool ssh_dstack_exists(SshDStack *stack)
{
    if (stack == NULL)
      return false;
    if (*stack == NULL)
      return false;
    return true;
}

/* Sort the entries in a way we have end certs before CA certs. */
static SshCertDBEntryList *
cm_entry_list_prefer_user(SshCMContext cm, SshCertDBEntryList *found)
{
    SshCertDBEntryList *result = ssh_certdb_entry_list_allocate(cm->db);
    SshCertDBEntryListNode list, next;
    bool rv;

    if (result == NULL)
      return found;

    if (found == NULL)
    {
        ssh_certdb_entry_list_free_all(cm->db, result);
        return NULL;
    }

    for (list = found->head; list && result; list = next)
    {
        SshCMCertificate cert = (SshCMCertificate)list->entry->context;
        SshCertDBEntry *entry;

        next = list->next;
        entry = ssh_certdb_entry_list_remove(cm->db, list);

        if (cert->is_ca || cert->acting_ca)
          rv = ssh_certdb_entry_list_add_tail(cm->db, result, entry);
        else
          rv = ssh_certdb_entry_list_add_head(cm->db, result, entry);

        if (!rv)
        {
            ssh_certdb_entry_list_free_all(cm->db, found);
            ssh_certdb_entry_list_free_all(cm->db, result);
            result = NULL;
        }
        ssh_certdb_release_entry(cm->db, entry);
    }
    if (result)
      ssh_certdb_entry_list_free_all(cm->db, found);

    return result;
}

/* The following function is the heart of all these things. It has
   been written to be restartable, thus is a bit hard to follow. */
static SshCMStatus
ssh_cm_find_internal(SshCMSearchContext *search)
{
    SshCMContext           cm     = search->cm;
    SshCMSearchConstraints constraints = search->end_cert;
    SshCertDBKey *keys;
    bool       keys_allocated;
    /* The chosen list. */
    SshCertDBEntryList *chosen, *comb;
    SshCertDBEntry     *entry;
    SshCertDBEntryList *found;
    /* The possible stack of lists. */
    SshDStack possible;
    unsigned int session_id;
    /* Assume that chosen list should be freed when leaving. */
    bool should_chosen_be_freed = true;
    bool should_comb_be_freed = true;
    /* A flag for termination of an search. Assuming that no such thing
       happens. */
    bool search_terminated = false;
    /* Make the search for the end user slightly different. */
    bool for_first, group_mode_on;
    SshCMStatus rv = SSH_CM_STATUS_FAILURE;
    /* The configured maximum path length allowed for any search within our
       library. (Sometimes longer chains are be allowed, but you should not
       count on that.) */
    size_t path_length = 0;

    SSH_DEBUG(SSH_D_HIGHOK, ("Certificate searching (re)started (%p).",
                             search));

    keys = NULL;
    keys_allocated = false;

    if (search->status != SSH_CM_STATUS_OK)
    {
        SSH_DEBUG(SSH_D_NETFAULT, ("Killed due error before CA searches."));
        SSH_DEBUG(SSH_D_HIGHOK,   ("Notes: %@",
                                   ssh_cm_render_state, search->state));

        /* Call the application callback and tell it that the operation
           has now expired and will be aborted. */
        cm_search_callback(search, search->status, NULL);

        /* Search has terminated. Thus handle the next one is exists. */
        search->terminated = true;
        return ssh_cm_operation_control(cm);
    }

    /* Handle the case of failure by too many restarts. */
    if (search->restarts > cm->config->max_restarts)
    {
        SSH_DEBUG(SSH_D_NETFAULT, ("Killed due too many restarts."));
        SSH_DEBUG(SSH_D_HIGHOK,   ("Notes: %@",
                                   ssh_cm_render_state, search->state));

        /* Call the application callback and tell it that the operation
           has now expired and will be aborted. */
        cm_search_callback(search, SSH_CM_STATUS_TIMEOUT, NULL);

        /* Search has terminated. Thus handle the next one is exists. */
        search->terminated = true;
        return ssh_cm_operation_control(cm);
    }

    /* Compute times before starting the loop. */
    if (ssh_cm_compute_validity_times(search) != SSH_CM_STATUS_OK)
    {
        SSH_DEBUG(SSH_D_NETFAULT, ("Time information incorrect."));
        SSH_DEBUG(SSH_D_HIGHOK,   ("Notes: %@",
                                   ssh_cm_render_state, search->state));

        ssh_cm_error_set(search,
                         SSH_CM_SSTATE_TIMES_UNAVAILABLE,
                         SSH_CM_ERROR_TIMES_UNAVAILABLE,
                         NULL,
                         NULL);

        cm_search_callback(search, SSH_CM_STATUS_FAILURE, NULL);

        /* Search has terminated. Thus handle the next one is exists. */
        search->terminated = true;
        return ssh_cm_operation_control(cm);
    }

    SSH_DEBUG(SSH_D_HIGHOK,
              ("Current time for the search: '%@'.",
               ssh_ber_time_render, &search->cur_time));

    /* Initialize the possible. We should not try to store the possible
       stack of lists thing in any way. */
    possible = NULL;

    chosen   = ssh_certdb_entry_list_allocate(cm->db);
    comb     = ssh_certdb_entry_list_allocate(cm->db);

    if (chosen == NULL || comb == NULL)
    {
        ssh_cm_error_set(search,
                         SSH_CM_SSTATE_DB_METHOD_FAILED,
                         SSH_CM_ERROR_MEMORY_ALLOC_FAILED,
                         NULL,
                         NULL);
        found = NULL;
        goto failure_in_search;
    }

    /* Get a new session identifier. We will update every certificate we
       touch. */
    session_id = cm->session_id;
    cm->session_id++;
    SSH_DEBUG(SSH_D_LOWOK,
              ("Allocating new cmi session id %d and restarting", session_id));

    /* Update the restarts counter. */
    search->restarts++;

    /* Start traveling the keys. */
    keys = constraints->keys;
    keys_allocated = false;

    /* Initialize the found list. */
    found         = NULL;
    for_first     = true;
    group_mode_on = false;

    /* Main loop. */
    while (1)
    {
        bool search_successful = false;

        /* First look for the certificate from the local database. */
        found = cm_search_local_dbs(search,
                                    SSH_CM_DATA_TYPE_CERTIFICATE,
                                    keys, constraints->rule);
        if (found != NULL)
        {
            SshCertDBEntryListNode node, prev;
            bool local_possible = false, multiple = false;

            for (node = found->head, prev = NULL; node; node = node->next)
            {
                if (prev)
                {
                    SshCMCertificate cert;
                    unsigned int iid, sid;

                    cert = (SshCMCertificate)node->entry->context;
                    sid = ssh_cm_cert_get_cache_id(cert);
                    cert = (SshCMCertificate)prev->entry->context;
                    iid = ssh_cm_cert_get_cache_id(cert);

                    if (!cm_failure_list_member(search, iid, sid))
                      local_possible = true;
                    multiple = true;
                }
                prev = node;
            }

              if (!multiple || local_possible)
              {
                  search_successful = true;
              }
              else
              {
                  ssh_certdb_entry_list_free_all(cm->db, found);
                  found = NULL;
              }
        }

        if (found == NULL)
        {
            /* Try from external databases then... */
            if (!constraints->local.cert)
              rv = cm_search_dbs(search,
                                 SSH_CM_DATA_TYPE_CERTIFICATE,
                                 keys, constraints->rule, &found);
            else
              rv = SSH_CM_STATUS_NOT_FOUND;

            switch (rv)
            {
              case SSH_CM_STATUS_OK:
                search_successful = true;
                break;
              case SSH_CM_STATUS_NOT_FOUND:
                ssh_cm_error_set(search,
                                 SSH_CM_SSTATE_CERT_NOT_FOUND,
                                 SSH_CM_ERROR_CERT_NOT_FOUND,
                                 NULL,
                                 NULL);
                search_successful = true;
                break;
              case SSH_CM_STATUS_SEARCHING:
                ssh_certdb_entry_list_free_all(cm->db, found);
                found = NULL;
                goto goaway;
              default:
                SSH_DEBUG(SSH_D_NETFAULT, ("Error searching external DB."));
                found = NULL;
                break;
            }
        }

        if (search_successful == false)
        {
          failure_in_search:
            SSH_DEBUG(SSH_D_HIGHOK, ("Notes: %@",
                                     ssh_cm_render_state, search->state));

            /* Let the application know as well ... */
            cm_search_callback(search, rv, NULL);
            ssh_certdb_entry_list_free_all(cm->db, found);
            found = NULL;

            /* ... and terminate search. */
            search_terminated = true;
            /* Return happily though. */
            rv = SSH_CM_STATUS_OK;
            goto goaway;
        }

        /* Check if the entry list contains anything. */
        if (ssh_certdb_entry_list_empty(found) != true)
        {
            SshCertDBEntryList *tmp;
            SshCertDBEntryListNode list, next;

            /* Sort found certs, user certs first. */
            tmp = cm_entry_list_prefer_user(cm, found);
            if (tmp != NULL)
            {
                found = tmp;
            }
            else
            {
                rv = SSH_CM_STATUS_NOT_FOUND;
                found = NULL;
                goto failure_in_search;
            }

            /* Traverse the list, apply constraints to filter out non
               suitable ones. */
            for (list = found->head; list; list = next)
            {
                /* Get the next. */
                next = list->next;

                /* Check the session id. */
                if (list->entry->session_id == session_id)
                {
                    /* Remove certificate from the entry list. */
                    ssh_cm_error_set(search,
                                     SSH_CM_SSTATE_CERT_CHAIN_LOOP,
                                     SSH_CM_ERROR_CERT_CHAIN_LOOP,
                                     NULL,
                                     NULL);
                    ssh_certdb_entry_list_free(cm->db, list);
                }
                else
                {
                    SshCMCertificate current, head;

                    /* Get the certificate from the search results.
                       Also, get the certificate 'current' possibly has
                       issued from the head of chosen certificates. */
                    current = (SshCMCertificate) list->entry->context;
                    if (ssh_certdb_entry_list_empty(chosen))
                      head = NULL;
                    else
                      head = (SshCMCertificate) chosen->head->entry->context;

                    SSH_DEBUG(SSH_D_MIDOK,
                              ("Applying constraints to: %@ and %@",
                               ssh_cm_render_certificate, current->cert,
                               ssh_cm_render_certificate,
                               head ? head->cert : current->cert));

                    switch (ssh_cm_cert_apply_constraints(search,
                                                          current, head,
                                                          for_first))
                    {
                      case SSH_CM_STATUS_NOT_VALID:
                        /* We believe that the search can still, however,
                           be valid given a suitable CA. */
                        SSH_DEBUG(SSH_D_MIDOK,
                                  ("CMI: Certificate validity can not yet "
                                   "be determined."));
                        /* Mark with current session id. */
                        list->entry->session_id = session_id;
                        break;
                      case SSH_CM_STATUS_CANNOT_BE_VALID:
                        SSH_DEBUG(SSH_D_HIGHOK,
                                  ("CMI: Certificate cannot be valid in "
                                   "this search."));
                        ssh_cm_error_set(search,
                                         SSH_CM_SSTATE_PATH_NOT_VERIFIED,
                                         SSH_CM_ERROR_PATH_NOT_VERIFIED,
                                         current,
                                         NULL);
                        ssh_certdb_entry_list_free(cm->db, list);
                        break;

                      case SSH_CM_STATUS_OK:
                        /* Mark with current session id. */
                        list->entry->session_id = session_id;

                        /* Throw the ca into the list. */
                        if (!ssh_certdb_entry_list_add_head(cm->db,
                                                            chosen,
                                                            list->entry))
                        {
                            ssh_cm_error_set(search,
                                             SSH_CM_SSTATE_DB_METHOD_FAILED,
                                             SSH_CM_ERROR_MEMORY_ALLOC_FAILED,
                                             NULL,
                                             NULL);
                            SSH_DEBUG(SSH_D_ERROR,
                                      ("Out of memory when verifying path"));
                            break;
                        }

                        /* Call the verify function. */
                        switch ((rv = ssh_cm_verify_path(search, chosen)))
                        {
                          case SSH_CM_STATUS_NOT_VALID:
                          case SSH_CM_STATUS_NOT_FOUND:
                            SSH_DEBUG(
                                    SSH_D_NETFAULT, ("CMI: Path is invalid."));
                            ssh_cm_error_set(search,
                                             SSH_CM_SSTATE_PATH_NOT_VERIFIED,
                                             SSH_CM_ERROR_PATH_NOT_VERIFIED,
                                             NULL,
                                             NULL);
                            break;

                          case SSH_CM_STATUS_SEARCHING:
                            SSH_DEBUG(SSH_D_MIDOK,
                                      ("CMI: Searching for a CRL..."));
                            ssh_certdb_entry_list_free_all(cm->db, found);
                            found = NULL;
                            goto goaway;

                          case SSH_CM_STATUS_OK:
                            /* Happily for us, we succeeded. */

                            SSH_DEBUG(SSH_D_HIGHOK, ("CMI: Path is good."));

                            /* Handle the group searching here, due we
                               have found yet another good path. */
                            if (constraints->group)
                            {
                                SshCertDBEntryList *dummy;

                                SSH_DEBUG(SSH_D_MIDOK, ("Group mode search."));

                                /* Add the tail to the tail of the combined
                                   list. */
                                (void) ssh_certdb_entry_list_add_tail(cm->db,
                                                                      comb,
                                                                      chosen->
                                                                      tail->
                                                                      entry);

                                /* Only if we are searching for CA's is
                                   the current "found" list of further
                                   interest. Otherwise, we will happily
                                   jump to the next end-entity
                                   search. */
                                if (ssh_certdb_entry_list_first(chosen) ==
                                    ssh_certdb_entry_list_last(chosen)
                                    && !ssh_certdb_entry_list_empty(found))
                                {
                                    group_mode_on = true;
                                    break;
                                }

                                ssh_certdb_entry_list_free_all(cm->db, found);
                                ssh_certdb_entry_list_free_all(cm->db, chosen);
                                chosen = NULL;
                                found = NULL;

                                /* The group mode will now be handled. */
                                group_mode_on = false;

                                /* Free all but the last of the lists in
                                   the stack. */
                                dummy = NULL;
                                while (ssh_dstack_exists(&possible))
                                {
                                    ssh_certdb_entry_list_free_all(cm->db,
                                                                   dummy);
                                    dummy = ssh_dstack_pop(&possible);
                                    path_length--;
                                }

                                /* Check if we can continue searching
                                   with another end certificate. */
                                if (ssh_certdb_entry_list_empty(dummy) != true)
                                {
                                    found = dummy;

                                    if ((chosen =
                                         ssh_certdb_entry_list_allocate(
                                                 cm->db))
                                        == NULL)
                                    {
                                        ssh_cm_error_set(
                                                search,
                                                SSH_CM_SSTATE_DB_METHOD_FAILED,
                                              SSH_CM_ERROR_MEMORY_ALLOC_FAILED,
                                                NULL,
                                                NULL);
                                        goto goaway;
                                    }

                                    /* Note. We need to update the
                                       session id. */
                                    session_id = cm->session_id;
                                    cm->session_id++;
                                    SSH_DEBUG(SSH_D_LOWOK,
                                              ("Allocating new cmi session "
                                               "id %d, without restart.",
                                               session_id));
                                    goto keep_searching;
                                }

                                ssh_certdb_entry_list_free_all(cm->db, dummy);

                                /* Set the chosen to be the comb list
                                   instead. */
                                ssh_certdb_entry_list_free_all(cm->db, chosen);
                                chosen = comb;
                                comb   = NULL;

                                /* Continue to call the callback. */
                            }

                            ssh_certdb_entry_list_free_all(cm->db, found);
                            found = NULL;

                            /* Callback. */
                            SSH_DEBUG(SSH_D_HIGHOK,
                                      ("Notes: %@",
                                       ssh_cm_render_state, search->state));

                            cm_search_callback(search, rv, chosen);

                            /* ...and the search is terminated. */
                            search_terminated = true;
                            /* Set up to leave. */
                            should_chosen_be_freed = false;
                            rv = SSH_CM_STATUS_OK;
                            goto goaway;

                          default:
                            SSH_DEBUG(SSH_D_NETFAULT,
                                      ("CMI: Path is invalid."));
                            SSH_DEBUG(SSH_D_HIGHOK,
                                      ("Notes: %@",
                                       ssh_cm_render_state, search->state));

                            /* Callback. Inform the application of the
                               error. */
                            cm_search_callback(search, rv, NULL);
                            ssh_certdb_entry_list_free_all(cm->db, found);
                            found = NULL;
                            /* ...and the search is terminated. */
                            search_terminated = true;

                            rv = SSH_CM_STATUS_OK;
                            goto goaway;
                          } /* End for switch(verify_path()) */


                        /* Not valid! Remove from the chosen list! */
                        ssh_certdb_entry_list_free(cm->db, chosen->head);
                        break;

                      default:
                        /* Now happens something that is not expected. */
                        ssh_fatal("ssh_cm_find_internal: "
                                  "bad certificate constraints.");
                        break;
                      } /* End for switch(apply_constraints) */

                    /* Seems that either the path didn't verify or the
                       certificate wasn't a trusted. */
                  } /* session id mismatch */
              } /* for each found */
          } /* if found */

        /* Seek for the keys of the next issuer! */

        if (group_mode_on)
        {
            SshCertDBEntryList *dummy;

            SSH_DEBUG(SSH_D_UNCOMMON, ("Delayed group mode handling."));

            /* The group mode will now be handled. */
            group_mode_on = false;

            ssh_certdb_entry_list_free_all(cm->db, found);
            ssh_certdb_entry_list_free_all(cm->db, chosen);
            found = NULL;
            chosen = NULL;

            /* Free all but the last of the lists in the stack. */
            dummy = NULL;
            while (ssh_dstack_exists(&possible))
            {
                ssh_certdb_entry_list_free_all(cm->db, dummy);
                dummy = ssh_dstack_pop(&possible);
                /* Remember to adjust the path length. */
                path_length--;
            }

            /* Check if we can continue searching with another end
               certificate. */
            if (ssh_certdb_entry_list_empty(dummy) != true)
            {
                /* Make sure that we continue searching. */
                found = dummy;
                if ((chosen = ssh_certdb_entry_list_allocate(cm->db)) == NULL)
                  goto goaway;

                session_id = cm->session_id;
                cm->session_id++;
                goto keep_searching;
            }

            ssh_certdb_entry_list_free_all(cm->db, dummy);

            /* Set the chosen to be the comb list instead. */
            chosen = comb;
            comb   = NULL;

            /* Continue to call the callback. */

            ssh_certdb_entry_list_free_all(cm->db, found);
            found = NULL;

            /* Callback. */
            SSH_DEBUG(SSH_D_HIGHOK,
                      ("Notes: %@", ssh_cm_render_state, search->state));

            cm_search_callback(search, rv, chosen);

            /* ...and the search is terminated. */
            search_terminated = true;
            /* Set up to leave. */
            should_chosen_be_freed = false;
            rv = SSH_CM_STATUS_OK;
            goto goaway;
        }

        /* The keep searching for group searches. */
      keep_searching:
        SSH_DEBUG(SSH_D_HIGHOK, ("Still possible paths, keep searching."));

        /* Free keys also. */
        if (keys_allocated)
          ssh_certdb_key_free(keys);
        keys = NULL;

        path_length++;
        if (cm->config->max_path_length <= path_length ||
            constraints->max_path_length <= path_length)
        {
            ssh_certdb_entry_list_free_all(cm->db, found);
            found = NULL;
        }

        while (keys == NULL)
        {
            /* Handle the stack structure. Pop from the stack if nothing
               found nil. */
            while (ssh_certdb_entry_list_empty(found) &&
                   ssh_dstack_exists(&possible))
            {
                ssh_certdb_entry_list_free_all(cm->db, found);
                found = ssh_dstack_pop(&possible);

                entry = ssh_certdb_entry_list_remove(cm->db, chosen->head);
                /* Enable re-use in path construction. */
                entry->session_id = 0;

                ssh_certdb_release_entry(cm->db, entry);
                path_length--;
            }

            /* Now check if nothing to do still. */
            if (ssh_certdb_entry_list_empty(found) == false)
            {
                SSH_ASSERT(found != NULL);
                SSH_ASSERT(found->head != NULL);
                entry = found->head->entry;
                ssh_certdb_entry_list_move(chosen, found->head);
                ssh_dstack_push(&possible, found);
                found = NULL;

                /* Check the keys. */
                if (entry->context != NULL)
                {
                    SshCMCertificate current;
                    current = entry->context;

                    /* Get the issuer keys. And remember that we have allocated
                       them. */
                    if (ssh_cm_key_set_from_cert(&keys,
                                                 SSH_CM_KEY_CLASS_ISSUER,
                                                 current))
                      keys_allocated = true;
                }
            }
            else
            {
                ssh_certdb_entry_list_free_all(cm->db, found);
                found = NULL;

                if (search->waiting)
                {
                    SSH_DEBUG(SSH_D_MIDOK,
                              ("Nothing found so far; waiting for results"));
                    goto goaway;
                }
                else
                {
                    goto end;
                }
            }
          } /* while (keys == NULL) */

        /* Next round is not the first round. */
        for_first = false;
      } /* while (mainloop) */

   end:

    SSH_DEBUG(SSH_D_NETFAULT, ("Returning from internal find after an error. "
                               "(%p)", search));
    SSH_DEBUG(SSH_D_HIGHOK,
              ("Notes: %@", ssh_cm_render_state, search->state));

    /* Hello? Cannot do more, and still haven't succeeded in
       finding the list. Exit. */

    if (ssh_certdb_entry_list_empty(comb))
    {
        cm_search_callback(search, SSH_CM_STATUS_NOT_FOUND, NULL);
    }
    else
    {
        cm_search_callback(search, SSH_CM_STATUS_OK, comb);
        should_comb_be_freed = false;
    }

    /* ...and the search is terminated. */
    search_terminated = true;
    /* Not too bad though, we want the upper caller to be happy enough. */
    rv = SSH_CM_STATUS_OK;

    /* The standard way of leaving this function. */
   goaway:

    /* Free stack. */
    while (ssh_dstack_exists(&possible))
    {
        SshCertDBEntryList *entry_list;
        /* Free the stack entry, which is just a list of
           entries. */
        entry_list = ssh_dstack_pop(&possible);
        ssh_certdb_entry_list_free_all(cm->db, entry_list);
    }

    /* Free the chosen list. */
    if (should_chosen_be_freed)
      ssh_certdb_entry_list_free_all(cm->db, chosen);

    if (should_comb_be_freed)
      ssh_certdb_entry_list_free_all(cm->db, comb);

    /* Free keys also. */
    if (keys_allocated)
      ssh_certdb_key_free(keys);

    SSH_DEBUG(SSH_D_HIGHOK, ("Stepping out from the internal find function."));

    /* Check whether next search could be launched. */
    if (search_terminated)
    {
        search->terminated = true;
        /* Call the OP's center for more operations. */
        return ssh_cm_operation_control(cm);
    }
    return rv;
}

SshCMStatus ssh_cm_operation_control(SshCMContext cm)
{
    SshCMSearchContext *tmp, *prev;
    SshCMStatus rv = SSH_CM_STATUS_OK;

    SSH_DEBUG(SSH_D_HIGHSTART, ("OP control."));
    if (cm->current == NULL)
    {
        if (cm->searching)
        {
            ssh_fatal("ssh_cm_operation_control: searching is set "
                      "even when current is NULL");
        }

        if (cm->stopping)
          cm_stopped(cm);

        return rv;
    }

    /* We don't continue if in callback. */
    if (cm->in_callback)
    {
        /* We are now continuing directly after performed a
           callback. Restart again from the bottom of the eventloop. */

        SSH_DEBUG(SSH_D_FAIL, ("Retrying later."));

        if (!cm->control_timeout_active)
        {
            cm->control_timeout_active = true;
            ssh_register_timeout(&cm->control_timeout,
                                 cm->config->timeout_seconds,
                                 cm->config->timeout_microseconds,
                                 ssh_cm_timeout_control, cm);
        }
        return rv;
    }

    /* Add one to the depth of the operation recursion. This should
       work to restrict the time taken by the code to do searches
       one time. E.g. the application gets some time too if it likes. */
    cm->operation_depth++;

    /* Is the current search terminated? */
    for (tmp = cm->current, prev = NULL;
         tmp;
         prev = tmp, tmp = tmp->next)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Checking expired searches %p status %u",
                                     tmp, tmp->terminated));

        /* Maybe search has timed out */
        if (tmp->terminated == false
            && cm->config->search_expire_timer > 0
            && (tmp->started + cm->config->search_expire_timer) <= ssh_time())
        {
            cm_search_callback(tmp, SSH_CM_STATUS_TIMEOUT, NULL);
            tmp->terminated = true;
        }

        if (tmp->terminated == true)
        {
            SSH_DEBUG(SSH_D_HIGHOK,
                      ("Removing finished search (%p, head %p).",
                       tmp, cm->current));

            tmp = ssh_cm_remove_search(cm, tmp, prev);

            /* Remove the related searches. */
            ssh_cm_edb_operation_remove(cm, tmp);

            /* Abort asynchronous verify operation. */
            if (tmp->async_op != NULL)
            {
                SSH_ASSERT(tmp->waiting > 0);
                tmp->waiting -= 1;

                ssh_operation_abort(tmp->async_op);
                tmp->async_op = NULL;
            }

            ssh_cm_search_free(tmp->end_cert);
            ssh_certdb_entry_list_free_all(cm->db, tmp->ca_cert);
            ssh_free(tmp->failure_list);
            if (tmp->error_string != NULL)
              ssh_free(tmp->error_string);
            ssh_free(tmp);
            tmp = prev;

            /* Check for trivial exit. */
            if (tmp == NULL)
              break;
        }
    }

    /* Control operation MAP */
    if (ssh_cm_map_control(cm->op_map))
    {
        if (!cm->map_timeout_active)
        {
            /* Notice; we register a longer timeout than default,
               therefore we use different context, even if the
               timeout function is the same */
            cm->map_timeout_active = true;
            ssh_register_timeout(&cm->map_timeout,
                                 cm->config->op_delay_msecs / 1000,
                                 1000 * (cm->config->op_delay_msecs % 1000),
                                 ssh_cm_map_timeout_control,
                                 cm);
        }
    }

    /* Check whether a new search should be started. */
    if (cm->searching && cm->operation_depth < cm->config->max_operation_depth)
    {
        SshCMSearchContext *search;

        /* Run the next search. */
        for (search = cm->current; search; search = search->next)
          if (search->waiting == 0 && search->terminated != true)
          {
              rv = ssh_cm_find_internal(search);
              break;
          }
    }
    else
    {
        if (cm->searching)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Too many levels of recursion. Trying again later."));

            /* Launch a timeout for later runs. Some applications may need
               timely answer and thus this is necessary. However, in general
               applications could handle the eventloop from their inner
               loops. */
            if (!cm->control_timeout_active)
            {
                cm->control_timeout_active = true;
                ssh_register_timeout(&cm->control_timeout,
                                     cm->config->timeout_seconds,
                                     cm->config->timeout_microseconds,
                                     ssh_cm_timeout_control,
                                     cm);
            }
        }
    }

    /* Check next operation expiry and register expiry timeout. */
    if (cm->config->search_expire_timer > 0)
    {
        SshTime current_time, next_expiry = 0;

        current_time = ssh_time();

        for (tmp = cm->current; tmp != NULL; tmp = tmp->next)
        {
            if (tmp->terminated == false
                && tmp->started + cm->config->search_expire_timer >=
                current_time
                && (next_expiry == 0
                    || tmp->started + cm->config->search_expire_timer <
                    next_expiry))
              next_expiry = tmp->started + cm->config->search_expire_timer;
        }

        if (next_expiry == 0)
        {
            if (cm->next_op_expire_timeout > 0)
            {
                SSH_DEBUG(SSH_D_LOWOK,
                          ("Cancelling operation expire timeout at %ds",
                           (int) (cm->next_op_expire_timeout - current_time)));
                ssh_cancel_timeout(&cm->op_expire_timeout);
            }
            cm->next_op_expire_timeout = 0;
        }
        else if (next_expiry > current_time
                 && next_expiry != cm->next_op_expire_timeout)
        {
            SSH_DEBUG(SSH_D_LOWOK,
                      ("Registering operation expire timeout to %ds",
                       (int) (next_expiry - current_time)));
            if (cm->next_op_expire_timeout > 0)
              ssh_cancel_timeout(&cm->op_expire_timeout);
            cm->next_op_expire_timeout = next_expiry;
            ssh_register_timeout(&cm->op_expire_timeout,
                                 (long)(next_expiry - current_time), 0,
                                 ssh_cm_timeout_op_expire, cm);
        }
    }

    /* Subtract one from the operation depth. */
    cm->operation_depth--;

    if (cm->stopping && cm->current == NULL)
      cm_stopped(cm);

    return rv;
}

/* Callback which restarts from the original certificate, with
   the CA now known. */
static void
ssh_cm_find_next(void *ctx,
                 SshCMSearchInfo info,
                 SshCertDBEntryList *list)
{
    SshCMSearchContext *search = ctx;

    SSH_DEBUG(SSH_D_HIGHOK, ("CA search terminated."));

    if (search->cm->stopping)
    {
        /* If we are stopping, this second search does not have to
           be made, actually we are only interested in reporting the
           failure to the PM. */
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Tried to start find next CA, when"
                   " CM is stopping, not done (%p).", search));
        cm_search_callback(search, SSH_CM_STATUS_FAILURE, NULL);

        /* Free the search, which was actually not ever started. */
        ssh_cm_search_free(search->end_cert);
        ssh_free(search->failure_list);
        ssh_free(search);
        return;
    }

    /* Copy the state. It might be that application may discover
       things through this information. */
    search->state  = info->state;

    if (info->status != SSH_CM_STATUS_OK)
    {
        /* Copy the info. */
        search->status = info->status;
        search->error = info->error;
        search->error_string =
          ssh_memdup(info->error_string, info->error_string_len);
        if (search->error_string != NULL)
          search->error_string_len = info->error_string_len;

        /* Add the search to the search list. */
        ssh_cm_add_search(search->cm, search);
        return;
    }

    /* Add the CA certificates to the following search. */
    search->ca_cert = list;

    /* Note that the current searching called us. */
    if (search->cm->current == search)
      ssh_fatal("ssh_cm_find_next: tried to restart itself.");

    /* Add the search to the search list. */
    ssh_cm_add_search(search->cm, search);
}

/* Routines for finding the certificate from the databases. */

static SshCMSearchContext *
ssh_cm_search_context_alloc(SshCMContext cm,
                            SshCMSearchConstraints constraints,
                            SshCMSearchResult search_callback,
                            void *caller_context)
{
    SshCMSearchContext *search;

    search = ssh_calloc(1, sizeof(*search));
    if (search != NULL)
    {
        /* Initialize the cm pointer. */
        search->cm   = cm;
        search->next = NULL;

        /* Init the status. */
        search->state  = SSH_CM_SSTATE_VOID;
        search->status = SSH_CM_STATUS_OK;

        /* Clear up. */
        search->terminated = false;

        search->async_completed = false;
        search->async_ok = false;
        search->waiting = 0;

        /* Set up search for end certificate, which is trusted. No specific
           ca defined. */
        search->end_cert = constraints;
        search->ca_cert  = NULL;

        /* Handle the restarts counter. */
        search->restarts = 0;

        /* Set up the application callback and context. */
        search->callback       = search_callback;
        search->search_context = caller_context;

        /* Failure list */
        search->failure_list_size = 0;
        search->failure_list = NULL;
    }

    return search;
}

SshCMStatus ssh_cm_find(SshCMContext cm,
                        SshCMSearchConstraints constraints,
                        SshCMSearchResult search_callback,
                        void *caller_context)
{
    SshCMSearchContext *search;

    if (cm->stopping)
      return SSH_CM_STATUS_FAILURE;

    search = ssh_cm_search_context_alloc(cm, constraints, search_callback,
                                         caller_context);
    if (search == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
        return SSH_CM_STATUS_FAILURE;
    }

    SSH_DEBUG(SSH_D_HIGHOK, ("A new search initiated (%p).", search));

    /* Add to the search list. */
    ssh_cm_add_search(cm, search);

    /* Add the search to the operation map. */
    ssh_cm_edb_operation_add(cm, search);

    /* Call the searching routine. */
    return ssh_cm_operation_control(cm);
}

SshCMStatus ssh_cm_find_path(SshCMContext cm,
                             SshCMSearchConstraints ca_constraints,
                             SshCMSearchConstraints end_constraints,
                             SshCMSearchResult search_callback,
                             void *caller_context)
{
    SshCMSearchContext *search;
    SshCMSearchContext *f_search;

    if (cm->stopping)
      return SSH_CM_STATUS_FAILURE;

    /* Search for the certificate (with the knowledge of the CA)! */
    f_search =
        ssh_cm_search_context_alloc(
                cm, end_constraints, search_callback,
                caller_context);
    if (f_search == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed for f_search"));
        return SSH_CM_STATUS_FAILURE;
    }

    /* Search which doesn't go the application yet, but to the another
       certificate searcher created above. */
    search = ssh_cm_search_context_alloc(cm, ca_constraints, ssh_cm_find_next,
                                         f_search);
    if (search == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed for search"));
        ssh_free(f_search);
        return SSH_CM_STATUS_FAILURE;
    }

    SSH_DEBUG(SSH_D_FAIL,
              ("A new search (with given CA) initiated (%p).", search));

    /* Push the first search to the list. */
    ssh_cm_add_search(cm, search);

    /* Add the search to the operation map. */
    ssh_cm_edb_operation_add(cm, search);
    /* Add the search to the operation map. */
    ssh_cm_edb_operation_add(cm, f_search);

    /* Call the searching routine. */
    return ssh_cm_operation_control(cm);
}

bool ssh_cm_reset(SshCMContext cm)
{
    /* Free old objects and caches */
    ssh_cm_map_free(cm->op_map);
    ssh_certdb_free(cm->db);
    ssh_cm_edb_free(&cm->edb);
    ssh_edb_nega_cache_free(cm->negacache);
    cm_cancel_timeouts(cm);

    /* Reset state variables */
    cm->operation_depth = 0;
    cm->session_id = 1;
    cm->searching = false;
    cm->in_callback = 0;
    cm->current = cm->last = NULL;

    ssh_ber_time_zero(&cm->ca_last_revoked_time);

    /* Re-initialize what we freed above */
    if (ssh_cm_init_local_cache(cm) == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Memory cache re-initialization failed."));
        goto failed;
    }

    cm->negacache =
      ssh_edb_nega_cache_allocate(cm->config->nega_cache_size,
                                  SSH_CM_KEY_TYPE_NUM,
                                  cm->config->nega_cache_invalid_secs);
    if (cm->negacache == NULL)
      goto failed;

    cm->op_map = ssh_cm_map_allocate();
    if (cm->op_map == NULL)
      goto failed;

    if (!ssh_cm_edb_init(&cm->edb))
      goto failed;
#ifdef SSHDIST_VALIDATOR_LDAP
    if (!ssh_cm_edb_ldap_init(cm, ""))
      goto failed;
#endif /* SSHDIST_VALIDATOR_LDAP */
    return true;

   failed:
    ssh_cm_free(cm);
    return false;
}

/* cmi.c */
#endif /* SSHDIST_CERT */
