/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate & CRL get routines.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

bool ssh_x509_cert_get_serial_number(SshX509Certificate c, SshMPInteger s)
{
    ssh_mprz_set(s, &c->serial_number);
    return !ssh_mprz_isnan(s);
}

bool ssh_x509_cert_get_subject_name(SshX509Certificate c, char **name)
{
    bool rv;
    rv = ssh_x509_name_pop_ldap_dn(c->subject_name, name);
    ssh_x509_name_reset(c->subject_name);
    return rv;
}

bool ssh_x509_cert_get_issuer_name(SshX509Certificate c, char **name)
{
    bool rv;
    rv = ssh_x509_name_pop_ldap_dn(c->issuer_name, name);
    ssh_x509_name_reset(c->issuer_name);
    return rv;
}

bool ssh_x509_cert_get_subject_name_der(SshX509Certificate c,
                                           unsigned char **der,
                                           size_t *der_len)
{
    bool rv;
    rv = ssh_x509_name_pop_der_dn(c->subject_name, der, der_len);
    ssh_x509_name_reset(c->subject_name);
    return rv;
}

bool ssh_x509_cert_get_issuer_name_der(SshX509Certificate c,
                                          unsigned char **der,
                                          size_t *der_len)
{
    bool rv;
    rv = ssh_x509_name_pop_der_dn(c->issuer_name, der, der_len);
    ssh_x509_name_reset(c->issuer_name);
    return rv;
}

bool ssh_x509_cert_get_subject_name_str(SshX509Certificate c, SshStr *str)
{
    bool rv;
    rv = ssh_x509_name_pop_str_dn(c->subject_name, str);
    ssh_x509_name_reset(c->subject_name);
    return rv;
}

bool ssh_x509_cert_get_issuer_name_str(SshX509Certificate c, SshStr *str)
{
    bool rv;
    rv = ssh_x509_name_pop_str_dn(c->issuer_name, str);
    ssh_x509_name_reset(c->issuer_name);
    return rv;
}

bool ssh_x509_cert_get_validity(SshX509Certificate c,
                                   SshBerTime not_before,
                                   SshBerTime not_after)
{
    if (ssh_ber_time_available(&c->not_before) == false ||
        ssh_ber_time_available(&c->not_after)  == false)
      return false;

    if (not_before)
      ssh_ber_time_set(not_before, &c->not_before);
    if (not_after)
      ssh_ber_time_set(not_after,  &c->not_after);
    return true;
}

bool ssh_x509_cert_get_public_key(SshX509Certificate c,
                                     SshPublicKey *key)
{
    if (c->subject_pkey.public_key == NULL)
    {
        *key = NULL;
        return false;
    }

    if (ssh_public_key_copy(c->subject_pkey.public_key, key) != SSH_CRYPTO_OK)
      return false;
    return true;
}

bool ssh_x509_cert_get_subject_unique_identifier(SshX509Certificate c,
                                                    unsigned char **buf,
                                                    size_t *buf_len)
{
    bool rv;
    rv = ssh_x509_name_pop_unique_identifier(c->subject_name, buf, buf_len);
    ssh_x509_name_reset(c->subject_name);
    return rv;
}

bool ssh_x509_cert_get_issuer_unique_identifier(SshX509Certificate c,
                                                   unsigned char **buf,
                                                   size_t *buf_len)
{
    bool rv;
    rv = ssh_x509_name_pop_unique_identifier(c->issuer_name, buf, buf_len);
    ssh_x509_name_reset(c->issuer_name);
    return rv;
}

/* Extensions; The return false if the extension is not available.
   These functions fill pointer to memory inside the certificate. */
bool ssh_x509_cert_get_subject_alternative_names(SshX509Certificate c,
                                                    SshX509Name *names,
                                                    bool *critical)
{
    if (ssh_x509_cert_ext_available(c,
                                    SSH_X509_EXT_SUBJECT_ALT_NAME, critical))
    {
        *names = c->extensions.subject_alt_names;
        return true;
    }
    else
      return false;
}

bool ssh_x509_cert_get_issuer_alternative_names(SshX509Certificate c,
                                                   SshX509Name *names,
                                                   bool *critical)
{
    if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_ISSUER_ALT_NAME, critical))
    {
        *names = c->extensions.issuer_alt_names;
        return true;
    }
    else
      return false;
}

bool ssh_x509_cert_get_private_key_usage_period(SshX509Certificate c,
                                                   SshBerTime not_before,
                                                   SshBerTime not_after,
                                                   bool *critical)
{
    if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_PRV_KEY_UP, critical))
    {
        if (not_before)
        {
            if (ssh_ber_time_available(&c->extensions.
                                       private_key_usage_not_before))
              ssh_ber_time_set(not_before,
                               &c->extensions.private_key_usage_not_before);
            else
              ssh_ber_time_zero(not_before);
        }
        if (not_after)
        {
            if (ssh_ber_time_available(&c->extensions.
                                       private_key_usage_not_after))
              ssh_ber_time_set(not_after,
                               &c->extensions.private_key_usage_not_after);
            else
              ssh_ber_time_zero(not_after);
        }
        return true;
    }
    else
      return false;
}

bool ssh_x509_cert_get_key_usage(SshX509Certificate c,
                                    SshX509UsageFlags *flags,
                                    bool *critical)
{
    if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_KEY_USAGE, critical))
    {
        if (c->extensions.ca)
          *flags =
            c->extensions.key_usage & c->subject_pkey.ca_key_usage_mask;
        else
          *flags =
            c->extensions.key_usage & c->subject_pkey.subject_key_usage_mask;
        return true;
    }
    else
      return false;
}

bool ssh_x509_cert_get_inhibit_any_policy(SshX509Certificate c,
                                             uint32_t *ncerts,
                                             bool *critical)
{
    if (ssh_x509_cert_ext_available(c,
                                    SSH_X509_EXT_INHIBIT_ANY_POLICY, critical))
    {
        *ncerts = c->extensions.inhibit_any_skip_certs;
        return true;
    }
    return false;
}

bool ssh_x509_cert_get_basic_constraints(SshX509Certificate c,
                                            size_t       *path_length,
                                            bool      *ca,
                                            bool      *critical)
{
    if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_BASIC_CNST, critical))
    {
        *path_length = c->extensions.path_len;
        *ca          = c->extensions.ca;
        return true;
    }
    else
      return false;
}

/* Get the authority key identifier. */
bool ssh_x509_cert_get_authority_key_id(SshX509Certificate c,
                                           SshX509ExtKeyId *id,
                                           bool *critical)
{
    if (c->extensions.issuer_key_id &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_AUTH_KEY_ID, critical))
    {
        *id = c->extensions.issuer_key_id;
        return true;
    }
    else
      return false;
}

/* Get the subject key identifier. */
bool ssh_x509_cert_get_subject_key_id(SshX509Certificate c,
                                         unsigned char **key_id,
                                         size_t         *key_id_len,
                                         bool *critical)
{
    if (c->extensions.subject_key_id &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_SUBJECT_KEY_ID, critical))
    {
        *key_id     = c->extensions.subject_key_id->key_id;
        *key_id_len = c->extensions.subject_key_id->key_id_len;
        return true;
    }
    else
      return false;
}

/* Get the policy info. */
bool
ssh_x509_cert_get_policy_info(SshX509Certificate c,
                              SshX509ExtPolicyInfo *pinfo,
                              bool *critical)
{
    if (c->extensions.policy_info &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_CERT_POLICIES, critical))
    {
        *pinfo    = c->extensions.policy_info;
        return true;
    }
    else
      return false;
}

/* Get the CRL distribution point. */
bool
ssh_x509_cert_get_crl_dist_points(SshX509Certificate c,
                                  SshX509ExtCRLDistPoints *points,
                                  bool *critical)
{
    if (c->extensions.crl_dp &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_CRL_DIST_POINTS, critical))
    {
        *points = c->extensions.crl_dp;
        return true;
    }
    else
      return false;
}

bool
ssh_x509_cert_get_freshest_crl(SshX509Certificate c,
                               SshX509ExtCRLDistPoints *fresh,
                               bool *critical)
{
    if (c->extensions.freshest_crl &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_FRESHEST_CRL, critical))
    {
        *fresh = c->extensions.freshest_crl;
        return true;
    }
    else
      return false;
}

/* Get the policy mappings. */
bool
ssh_x509_cert_get_policy_mappings(SshX509Certificate c,
                                  SshX509ExtPolicyMappings *pmappings,
                                  bool *critical)
{
    if (c->extensions.policy_mappings &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_POLICY_MAPPINGS, critical))
    {
        *pmappings = c->extensions.policy_mappings;
        return true;
    }
    else
      return false;
}

/* Get the authority information access. */
bool
ssh_x509_cert_get_auth_info_access(SshX509Certificate c,
                                   SshX509ExtInfoAccess *access,
                                   bool *critical)
{
    if (c->extensions.auth_info_access &&
        ssh_x509_cert_ext_available(c,
                                    SSH_X509_EXT_AUTH_INFO_ACCESS, critical))
    {
        *access   = c->extensions.auth_info_access;
        return true;
    }
    else
      return false;
}

/* Get the subject information access. */
bool
ssh_x509_cert_get_subject_info_access(SshX509Certificate c,
                                      SshX509ExtInfoAccess *access,
                                      bool *critical)
{
    if (c->extensions.subject_info_access &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_SUBJECT_INFO_ACCESS,
                                    critical))
    {
        *access   = c->extensions.subject_info_access;
        return true;
    }
    else
      return false;
}


bool
ssh_x509_cert_get_netscape_comment(SshX509Certificate c,
                                   SshStr *comment,
                                   bool *critical)
{
    if (c->extensions.netscape_comment &&
        ssh_x509_cert_ext_available(
                c, SSH_X509_EXT_NETSCAPE_COMMENT, critical))
    {
        *comment = c->extensions.netscape_comment;
        return true;
    }
    else
      return false;

}

bool
ssh_x509_cert_get_cert_template_name(SshX509Certificate c,
                                     SshStr *name,
                                     bool *critical)
{
    if (c->extensions.cert_template_name &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_CERT_TEMPLATE_NAME,
                                    critical))
    {
        *name = c->extensions.cert_template_name;
        return true;
    }
    else
      return false;

}

bool
ssh_x509_cert_get_qcstatements(SshX509Certificate c,
                               SshX509ExtQCStatement *qcs,
                               bool *critical)
{
    if (c->extensions.qcstatements &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_QCSTATEMENTS,
                                    critical))
    {
        *qcs = c->extensions.qcstatements;
        return true;
    }
    else
      return false;
}

bool
ssh_x509_cert_get_subject_dir_attributes(SshX509Certificate c,
                                         SshX509ExtDirAttribute *attr,
                                         bool *critical)
{
    if (c->extensions.subject_directory_attr &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_SUBJECT_DIR_ATTR,
                                    critical))
    {
        *attr = c->extensions.subject_directory_attr;
        return true;
    }
    else
      return false;
}

bool
ssh_x509_cert_get_unknown_extension(SshX509Certificate c,
                                    SshX509ExtUnknown *unknown,
                                    bool *critical)
{
    if (c->extensions.unknown &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_UNKNOWN, critical))
    {
        *unknown = c->extensions.unknown;
        return true;
    }
    else
      return false;
}

/* Get the name constraints. */
bool
ssh_x509_cert_get_name_constraints(SshX509Certificate c,
                                   SshX509GeneralSubtree *permitted,
                                   SshX509GeneralSubtree *excluded,
                                   bool *critical)
{
    if (ssh_x509_cert_ext_available(c, SSH_X509_EXT_NAME_CNST, critical))
    {
        *permitted = c->extensions.name_const_permitted;
        *excluded  = c->extensions.name_const_excluded;
        return true;
    }
    else
      return false;
}

bool
ssh_x509_cert_get_subject_directory_attributes(SshX509Certificate c,
                                               SshX509ExtDirAttribute *dattr,
                                               bool *critical)
{
    if (c->extensions.subject_directory_attr &&
        ssh_x509_cert_ext_available(
                c, SSH_X509_EXT_SUBJECT_DIR_ATTR, critical))
    {
        *dattr = c->extensions.subject_directory_attr;
        return true;
    }
    else
      return false;
}

/* Get the policy constraints. */
bool
ssh_x509_cert_get_policy_constraints(SshX509Certificate c,
                                     SshX509ExtPolicyConstraints *policy,
                                     bool *critical)
{
    if (c->extensions.policy_const &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_POLICY_CNST, critical))
    {
        *policy = c->extensions.policy_const;
        return true;
    }
    else
      return false;
}

/* Get the extended key usage field. */
bool
ssh_x509_cert_get_ext_key_usage(SshX509Certificate c,
                                SshX509OidList *ext_key_usage,
                                bool *critical)
{
    if (c->extensions.ext_key_usage &&
        ssh_x509_cert_ext_available(c, SSH_X509_EXT_EXT_KEY_USAGE, critical))
    {
        *ext_key_usage = c->extensions.ext_key_usage;
        return true;
    }
    else
      return false;
}

bool
ssh_x509_cert_get_attribute(SshX509Certificate c,
                            SshX509Attribute *attribute)
{
    if (c->attributes)
    {
        *attribute = c->attributes;
        return true;
    }
    else
      return false;
}

/**** CRLs */

bool ssh_x509_crl_get_issuer_name(SshX509Crl crl, char **name)
{
    bool rv;
    rv = ssh_x509_name_pop_ldap_dn(crl->issuer_name, name);
    ssh_x509_name_reset(crl->issuer_name);
    return rv;
}

bool ssh_x509_crl_get_issuer_name_der(SshX509Crl crl,
                                         unsigned char **der,
                                         size_t *der_len)
{
    bool rv;
    rv = ssh_x509_name_pop_der_dn(crl->issuer_name, der, der_len);
    ssh_x509_name_reset(crl->issuer_name);
    return rv;
}

bool ssh_x509_crl_get_issuer_name_str(SshX509Crl crl, SshStr *name_str)
{
    bool rv;
    rv = ssh_x509_name_pop_str_dn(crl->issuer_name, name_str);
    ssh_x509_name_reset(crl->issuer_name);
    return rv;
}

bool ssh_x509_crl_get_update_times(SshX509Crl crl,
                                      SshBerTime this_update,
                                      SshBerTime next_update)
{
    if (this_update)
    {
        if (ssh_ber_time_available(&crl->this_update))
          ssh_ber_time_set(this_update, &crl->this_update);
        else
          ssh_ber_time_zero(this_update);
    }
    if (next_update)
    {
        if (ssh_ber_time_available(&crl->next_update))
          ssh_ber_time_set(next_update, &crl->next_update);
        else
          ssh_ber_time_zero(next_update);
    }
    return true;
}

bool ssh_x509_crl_get_issuer_alternative_names(SshX509Crl crl,
                                                  SshX509Name *names,
                                                  bool *critical)
{
    if (ssh_x509_crl_ext_available(crl, SSH_X509_CRL_EXT_ISSUER_ALT_NAME,
                                   critical))
    {
        *names = crl->extensions.issuer_alt_names;
        return true;
    }
    return false;
}

bool
ssh_x509_crl_get_authority_key_id(SshX509Crl crl,
                                  SshX509ExtKeyId *id,
                                  bool *critical)
{
    if (crl->extensions.auth_key_id &&
        ssh_x509_crl_ext_available(
                crl, SSH_X509_CRL_EXT_AUTH_KEY_ID, critical))
    {
        *id = crl->extensions.auth_key_id;
        return true;
    }
    else
      return false;
}

bool
ssh_x509_crl_get_issuing_dist_point(SshX509Crl crl,
                                    SshX509ExtIssuingDistPoint *dist_point,
                                    bool *critical)
{
    if (crl->extensions.dist_point &&
        ssh_x509_crl_ext_available(crl, SSH_X509_CRL_EXT_ISSUING_DIST_POINT,
                                   critical))
    {
        *dist_point = crl->extensions.dist_point;
        return true;
    }
    else
      return false;
}

bool ssh_x509_crl_get_crl_number(SshX509Crl crl,
                                    SshMPInteger crl_number,
                                    bool *critical)
{
    if (ssh_x509_crl_ext_available(crl, SSH_X509_CRL_EXT_CRL_NUMBER, critical)
        && !(ssh_mprz_cmp_ui(&crl->extensions.crl_number, 0) < 0))
    {
        ssh_mprz_set(crl_number, &crl->extensions.crl_number);
        return true;
    }
    else
      return false;
}

bool ssh_x509_crl_get_delta_crl_indicator(SshX509Crl crl,
                                             SshMPInteger delta,
                                             bool *critical)
{
    if (ssh_x509_crl_ext_available(
                crl, SSH_X509_CRL_EXT_DELTA_CRL_IND, critical)
        && !(ssh_mprz_cmp_ui(&crl->extensions.delta_crl_ind, 0) < 0))
    {
        ssh_mprz_set(delta, &crl->extensions.delta_crl_ind);
        return true;
    }
    else
      return false;
}

SshX509RevokedCerts ssh_x509_crl_get_revoked(SshX509Crl crl)
{
    return crl->revoked;
}

SshX509RevokedCerts ssh_x509_revoked_get_next(SshX509RevokedCerts revoked)
{
    return revoked->next;
}

bool ssh_x509_revoked_get_serial_number(SshX509RevokedCerts revoked,
                                           SshMPInteger s)
{
    ssh_mprz_set(s, &revoked->serial_number);
    return true;
}

bool ssh_x509_revoked_get_revocation_date(SshX509RevokedCerts revoked,
                                             SshBerTime ber_time)
{
    if (ssh_ber_time_available(&revoked->revocation_date) == false)
      return false;
    ssh_ber_time_set(ber_time, &revoked->revocation_date);
    return true;
}

bool ssh_x509_revoked_get_certificate_issuer(SshX509RevokedCerts revoked,
                                                SshX509Name *names,
                                                bool *critical)
{
    if (ssh_x509_revoked_ext_available(revoked,
                                       SSH_X509_CRL_ENTRY_EXT_CERT_ISSUER,
                                       critical))
    {
        *names = revoked->extensions.certificate_issuer;
        return true;
    }
    else
      return false;
}

bool ssh_x509_revoked_get_reason_code(SshX509RevokedCerts revoked,
                                         SshX509CRLReasonCode *reason_code,
                                         bool *critical)
{
    if (ssh_x509_revoked_ext_available(revoked,
                                       SSH_X509_CRL_ENTRY_EXT_REASON_CODE,
                                       critical))
    {
        *reason_code = revoked->extensions.reason_code;
        return true;
    }
    else
      return false;
}

bool ssh_x509_revoked_get_hold_instruction_code(SshX509RevokedCerts revoked,
                                                   char **object_identifier,
                                                   bool *critical)
{
    *object_identifier = NULL;

    if (revoked->extensions.hold_inst_code &&
        ssh_x509_revoked_ext_available(revoked,
                                       SSH_X509_CRL_ENTRY_EXT_REASON_CODE,
                                       critical))
    {
        *object_identifier = ssh_strdup(revoked->extensions.hold_inst_code);
        if (*object_identifier == NULL)
          return false;

        return true;
    }
    else
      return false;
}

bool ssh_x509_revoked_get_invalidity_date(SshX509RevokedCerts revoked,
                                             SshBerTime date,
                                             bool *critical)
{
    if (ssh_x509_revoked_ext_available(revoked,
                                       SSH_X509_CRL_ENTRY_EXT_INVALIDITY_DATE,
                                       critical))
    {
        if (!ssh_ber_time_available(&revoked->extensions.invalidity_date))
          return false;
        ssh_ber_time_set(date, &revoked->extensions.invalidity_date);
        return true;
    }
    else
      return false;
}

/* x509get.c */
#endif /* SSHDIST_CERT */
