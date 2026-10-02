/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Credentials may be valid for multiple groups. Credentials may be
   knowledge of PSK, certificate used, IKEv1 Extented Authentication,
   Radius authentication, or EAP
*/

#include "sshincludes.h"
#include "pad_authorization_local.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IKE_CERT_AUTH
#include "x509.h"
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
#include "sshradius.h"
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

#include "sshutf8.h"
#include "sshmatch.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmAuthorizationLocal"

/* Match RADIUS AVP value `value' to the pattern `pattern'.  The
   argument `description' gives description about the value type. */
#define SSH_PM_MATCH_RADIUS_AVP(description, value, pattern)    \
do                                                              \
  {                                                             \
    /* temporary casts until library API is changed */          \
    bool s = ssh_match_pattern((const char *) value, pattern); \
                                                                \
    SSH_DEBUG(SSH_D_LOWOK, ("AVP %s `%s' %s pattern `%s'",      \
                            (description), (value),             \
                            s ? "matches" : "does not match",   \
                            (pattern)));                        \
    if (s)                                                      \
      goto success;                                             \
  }                                                             \
while (0)

/* An authorization object. */
struct SshPmAuthorizationLocalRec
{
    /* Known authorization groups. */
    SshPmAuthorizationGroup groups;
};

/* A constraint. */
struct SshPmAuthorizationConstraintRec
{
    struct SshPmAuthorizationConstraintRec *next;

    SshPmConstraintType type;
    SshPmIdentityType identity_type;

    char *field;
    char *pattern;

    SshPmAuthMethod auth_method;
};

typedef struct SshPmAuthorizationConstraintRec *SshPmAuthorizationConstraint;

/* An authorization group. */
struct SshPmAuthorizationGroupRec
{
    /* Link field used when the group is added to the authorization
       object. */
    struct SshPmAuthorizationGroupRec *next;

    /* Flags. */
    uint32_t is_new : 1;      /* Added after the last purge. */

    /* Number of reference to this group. */
    uint16_t refcount;

    /* Group ID. */
    uint16_t group_id;

    /* Group constraints. */
    SshPmAuthorizationConstraint constraints;
};

#ifdef SSHDIST_IKE_CERT_AUTH
/* Cached authentication data during one certificate authorization
   check. */
struct SshPmAuthDataCacheRec
{
    SshX509Certificate cert;      /* End-user certificate. */
    SshX509Certificate ca_cert;   /* CA certificate. */
};
typedef struct SshPmAuthDataCacheRec SshPmAuthDataCacheStruct;
typedef struct SshPmAuthDataCacheRec *SshPmAuthDataCache;
#endif /* SSHDIST_IKE_CERT_AUTH */


/************** Creating and destroying authorization objects ***************/

SshPmAuthorizationLocal
ssh_pm_authorization_local_create(void)
{
    SshPmAuthorizationLocal local;

    local = ssh_calloc(1, sizeof(*local));

    return local;
}


void
ssh_pm_authorization_local_destroy(SshPmAuthorizationLocal auth)
{
    if (auth == NULL)
      return;

    while (auth->groups)
    {
        SshPmAuthorizationGroup group;

        group = auth->groups;
        auth->groups = group->next;

        ssh_pm_authorization_group_destroy(group);
    }
    ssh_free(auth);
}


void
ssh_pm_authorization_local_purge(SshPmAuthorizationLocal authorization,
                                 bool purge_old)
{
    SshPmAuthorizationGroup *groupp;

    for (groupp = &authorization->groups; *groupp; )
    {
        SshPmAuthorizationGroup group = *groupp;

        if ((purge_old && !group->is_new) || (!purge_old && group->is_new))
        {
            /* Purge this group. */
            *groupp = group->next;
            ssh_pm_authorization_group_destroy(group);
        }
        else
        {
            /* Move forward. */
            group->is_new = 0;
            groupp = &(*groupp)->next;
        }
    }
}


/********************** Creating authorization groups ***********************/

SshPmAuthorizationGroup
ssh_pm_authorization_group_create(uint32_t group_id)
{
    SshPmAuthorizationGroup group;

    group = ssh_calloc(1, sizeof(*group));
    if (group == NULL)
      return NULL;

    group->refcount = 1;
    group->group_id = group_id;

    return group;
}


void
ssh_pm_authorization_group_destroy(SshPmAuthorizationGroup group)
{
    if (group == NULL)
      return;

    if (--group->refcount > 0)
      /* This was not the last reference. */
      return;

    /* Free this group. */

    while (group->constraints)
    {
        SshPmAuthorizationConstraint c;

        c = group->constraints;
        group->constraints = c->next;

        ssh_free(c->field);
        ssh_free(c->pattern);
        ssh_free(c);
    }

    ssh_free(group);
}


void
ssh_pm_authorization_add_group(SshPmAuthorizationLocal authorization,
                               SshPmAuthorizationGroup group)
{
    group->next = authorization->groups;
    authorization->groups = group;

    /* This is a new group in this authorization module. */
    group->is_new = 1;

    /* And we take one reference of the group. */
    group->refcount++;
}


void
ssh_pm_authorization_group_set_id(SshPmAuthorizationGroup group,
                                  uint32_t group_id)
{
    SSH_ASSERT(group != NULL);
    group->group_id = group_id;
}


uint32_t
ssh_pm_authorization_group_get_id(SshPmAuthorizationGroup group)
{
    SSH_ASSERT(group != NULL);
    return group->group_id;
}

/* Add constraint to group */
static bool
ag_add_constraint(SshPmAuthorizationGroup group,
                  SshPmIdentityType identity_type,
                  SshPmConstraintType constraint_type,
                  const char *constraint_field,
                  const char *constraint_pattern,
                  SshPmAuthMethod auth_method)
{
    SshPmAuthorizationConstraint c = NULL;

    c = ssh_calloc(1, sizeof(*c));
    if (c == NULL)
      goto error;

    c->type = constraint_type;
    c->identity_type = identity_type;

    if (constraint_pattern)
    {
        c->pattern = ssh_strdup(constraint_pattern);
        if (c->pattern == NULL)
          goto error;
    }

    if (constraint_field)
    {
        c->field = ssh_strdup(constraint_field);
        if (c->field == NULL)
          goto error;
    }

    c->auth_method = auth_method;

    c->next = group->constraints;
    group->constraints = c;

    return true;

    /* Error handling. */
   error:
    if (c)
    {
        ssh_free(c->pattern);
        ssh_free(c->field);
        ssh_free(c);
    }
    return false;

}


bool
ssh_authorization_group_add_psk_constraint(
                                        SshPmAuthorizationGroup group,
                                        SshPmIdentityType identity_type,
                                        const char *constraint_pattern)
{
    return ag_add_constraint(group,
                             identity_type, SSH_PM_CONSTRAIN_PSK_SUBJECT,
                             NULL,
                             constraint_pattern, SSH_PM_AUTH_NONE);
}


bool
ssh_authorization_group_add_cert_constraint(
                                        SshPmAuthorizationGroup group,
                                        SshPmIdentityType identity_type,
                                        SshPmConstraintType constraint_type,
                                        const char *constraint_pattern)
{
    if (identity_type == SSH_PM_IDENTITY_KEY_ID
#ifdef SSHDIST_IKE_ID_LIST
        || identity_type == SSH_PM_IDENTITY_ID_LIST
#endif /* SSHDIST_IKE_ID_LIST */
        )
    {
        SSH_DEBUG(
                SSH_D_FAIL,
                ("Invalid ID type %u for a certificate constraint",
                 identity_type));
        return false;
    }

    return ag_add_constraint(group,
                             identity_type, constraint_type,
                             NULL,
                             constraint_pattern, SSH_PM_AUTH_NONE);
}


#ifdef SSHDIST_IPSEC_XAUTH_SERVER
bool
ssh_authorization_group_add_xauth_constraint(
                                        SshPmAuthorizationGroup group,
                                        SshPmConstraintType constraint_type,
                                        const char *constraint_field,
                                        const char *constraint_pattern)
{
    return ag_add_constraint(group,
                             0, constraint_type,
                             constraint_field,
                             constraint_pattern,
                             SSH_PM_AUTH_NONE);
}
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

#ifdef SSHDIST_IKE_EAP_AUTH
bool
ssh_authorization_group_add_eap_subject_constraint(
                                        SshPmAuthorizationGroup group,
                                        SshPmIdentityType identity_type,
                                        const char *constraint_pattern)
{
    return ag_add_constraint(group,
                             identity_type, SSH_PM_CONSTRAIN_EAP_SUBJECT,
                             NULL,
                             constraint_pattern, SSH_PM_AUTH_NONE);
}


bool ssh_authorization_group_add_eap_constraint(
                                        SshPmAuthorizationGroup group,
                                        SshPmAuthMethod auth_method)
{
    return ag_add_constraint(group,
                             0,
                             SSH_PM_CONSTRAIN_EAP_AUTH_METHOD,
                             NULL,
                             NULL,
                             auth_method);
}
#endif /* SSHDIST_IKE_EAP_AUTH */

/******************** Authorization callback for PM API *********************/

#ifdef SSHDIST_IKE_CERT_AUTH
/* Check whether the certificate `cert' matches constraint `c'.  The
   argument `subject' specifies whether the subject or the issuer
   names are matched. */























































































































































static bool
ssh_pm_check_cert_subject(SshPmAuthorizationConstraint c,
                          SshX509Certificate cert, bool subject)
{
    bool result;
    char *value;
    char buf[256];

    SSH_ASSERT(c->pattern != NULL);

    if (c->identity_type == SSH_PM_IDENTITY_DN)
    {
        if (subject)
          result = ssh_x509_cert_get_subject_name(cert, &value);
        else
          result = ssh_x509_cert_get_issuer_name(cert, &value);

        if (!result)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Could not get %s name",
                                   subject ? "subject" : "issuer"));
            return false;
        }

        if (ssh_match_pattern(value, c->pattern))
        {
            SSH_DEBUG(SSH_D_LOWOK,
                      ("%s name `%s' matches pattern `%s'",
                       subject ? "Subject" : "Issuer",
                       value, c->pattern));
            ssh_free(value);
            return true;
        }
        ssh_free(value);
    }
    else
    {
        SshX509Name altnames;
        bool critical;
        unsigned char *ucp;
        size_t len;

        if (subject)
          result = ssh_x509_cert_get_subject_alternative_names(cert, &altnames,
                                                               &critical);
        else
          result = ssh_x509_cert_get_issuer_alternative_names(cert, &altnames,
                                                              &critical);
        if (!result)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Could not get %s alternative names",
                                   subject ? "subject" : "issuer"));
            return false;
        }

        switch (c->identity_type)
        {
          case SSH_PM_IDENTITY_DN:
          case SSH_PM_IDENTITY_KEY_ID:
#ifdef SSHDIST_IKE_ID_LIST
          case SSH_PM_IDENTITY_ID_LIST:
#endif /* SSHDIST_IKE_ID_LIST */
            SSH_NOTREACHED;
            break;

          case SSH_PM_IDENTITY_IP:
            while (ssh_x509_name_pop_ip(altnames, &ucp, &len))
            {
                SshIpAddrStruct addr;

                if (len == 4)
                  SSH_IP4_DECODE(&addr, ucp);
                else if (len == 16)
                  SSH_IP6_DECODE(&addr, ucp);
                else
                  continue;

                ssh_ipaddr_print(&addr, buf, sizeof(buf));
                if (ssh_match_pattern(buf, c->pattern))
                {
                    SSH_DEBUG(SSH_D_LOWOK,
                              ("IP address `%s' matches pattern `%s'",
                               buf, c->pattern));
                    ssh_free(ucp);
                    ssh_x509_name_reset(altnames);
                    return true;
                }
                ssh_free(ucp);
            }
            ssh_x509_name_reset(altnames);
            break;

          case SSH_PM_IDENTITY_FQDN:
            while (ssh_x509_name_pop_dns(altnames, &value))
            {
                if (ssh_match_pattern(value, c->pattern))
                {
                    SSH_DEBUG(SSH_D_LOWOK,
                              ("FQDN `%s' matches pattern `%s'",
                               value, c->pattern));
                    ssh_free(value);
                    ssh_x509_name_reset(altnames);
                    return true;
                }
                ssh_free(value);
            }
            ssh_x509_name_reset(altnames);
            break;

          case SSH_PM_IDENTITY_RFC822:
            while (ssh_x509_name_pop_email(altnames, &value))
            {
                if (ssh_match_pattern(value, c->pattern))
                {
                    SSH_DEBUG(SSH_D_LOWOK,
                              ("RFC822 name `%s' matches pattern `%s'",
                               value, c->pattern));
                    ssh_free(value);
                    ssh_x509_name_reset(altnames);
                    return true;
                }
                ssh_free(value);
            }
            ssh_x509_name_reset(altnames);
            break;
          default:
            SSH_NOTREACHED;
            break;
        }
    }

    SSH_DEBUG(SSH_D_FAIL, ("No matching name found"));

    return false;
}
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
/* Check whether the RADIUS AVPs of the request `req' match
   constraints `c'. */
static bool
ssh_pm_check_xauth_radius(SshPmAuthorizationConstraint c,
                          SshRadiusClientRequest req)
{
    const SshRadiusAvpInfoStruct *info;
    SshRadiusClientReplyEnumeratorStruct e;
    unsigned char *value;
    size_t value_len;
    char buf[261];    /* This is enough for all RADIUS attributes. */
    size_t len;
    SshChrConv conv = NULL;
    SshIpAddrStruct ip;
    bool result = false;

    if (c->field == NULL)
      return false;

    info = ssh_radius_avp_info_name(c->field);
    if (info == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Unknown RADIUS AVP field `%s'", c->field));
        goto out;
    }

    ssh_radius_client_reply_enumerate_init(&e,req,
                                           SSH_RADIUS_VENDOR_ID_NONE,
                                           info->type);
    while (ssh_radius_client_reply_enumerate_next(&e, NULL, NULL,
                                                  &value, &value_len)
           == SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
        switch (info->value_type)
        {
          case SSH_RADIUS_AVP_VALUE_TEXT:
            if (conv == NULL)
            {
                conv = ssh_charset_init(SSH_CHARSET_UTF8,
                                        SSH_CHARSET_ISO_LATIN_1);
                if (conv == NULL)
                {
                    SSH_DEBUG(SSH_D_ERROR,
                              ("Could not create charset conversion object"));
                    goto out;
                }
            }

            len = ssh_charset_convert(
                    conv, value, value_len, buf, sizeof(buf));
            SSH_ASSERT(len < sizeof(buf));
            buf[len] = '\0';

            SSH_PM_MATCH_RADIUS_AVP("text", buf, c->pattern);
            break;

          case SSH_RADIUS_AVP_VALUE_STRING:
            SSH_ASSERT(value_len < sizeof(buf));

            memcpy(buf, value, value_len);
            buf[value_len] = '\0';

            SSH_PM_MATCH_RADIUS_AVP("string", buf, c->pattern);
            break;

          case SSH_RADIUS_AVP_VALUE_ADDRESS:
          case SSH_RADIUS_AVP_VALUE_IPV6_ADDRESS:
            if (value_len == 4)
              SSH_IP4_DECODE(&ip, value);
            else if (value_len == 16)
              SSH_IP6_DECODE(&ip, value);
            else
            {
                SSH_DEBUG(SSH_D_UNCOMMON, ("Invalid IP address length %d",
                                           value_len));
                continue;
            }

            ssh_ipaddr_print(&ip, buf, sizeof(buf));

            SSH_PM_MATCH_RADIUS_AVP("IP address", buf, c->pattern);
            break;

          case SSH_RADIUS_AVP_VALUE_INTEGER:
            if (value_len == 4)
            {
                uint32_t ival = SSH_GET_32BIT(value);

                ssh_snprintf(buf, sizeof(buf), "%u",
                             (unsigned int) ival);
            }
            else
            {
                SSH_DEBUG(SSH_D_UNCOMMON, ("Invalid integer length %d",
                                           value_len));
                continue;
            }

            SSH_PM_MATCH_RADIUS_AVP("integer", buf, c->pattern);
            break;

          case SSH_RADIUS_AVP_VALUE_TIME:
            if (value_len == 4)
            {
                uint32_t ival = SSH_GET_32BIT(value);
                char *cp;

                cp = ssh_time_string((SshTime) ival);
                if (cp == NULL)
                {
                    SSH_DEBUG(
                            SSH_D_ERROR, ("Could not convert time to string"));
                    continue;
                }
                len = strlen(cp);
                if (len >= sizeof(buf))
                  len = sizeof(buf) - 1;

                memcpy(buf, cp, len);
                buf[len] = '\0';

                ssh_free(cp);
            }
            else
            {
                SSH_DEBUG(
                        SSH_D_UNCOMMON, ("Invalid time length %d", value_len));
                continue;
            }

            SSH_PM_MATCH_RADIUS_AVP("time", buf, c->pattern);
            break;

          case SSH_RADIUS_AVP_VALUE_TAG_STRING:
            if (value_len == 0)
            {
                SSH_DEBUG(SSH_D_UNCOMMON, ("Invalid tag-string length 0"));
                continue;
            }

            ssh_snprintf(buf, sizeof(buf), "%u:%.*s",
                         value[0], (int) value_len - 1, value + 1);

            SSH_PM_MATCH_RADIUS_AVP("tag-string", buf, c->pattern);
            break;

          case SSH_RADIUS_AVP_VALUE_TAG_INTEGER:
            if (value_len == 5)
            {
                uint32_t ival = SSH_GET_32BIT(value + 1);

                ssh_snprintf(buf, sizeof(buf),
                             "%u:%u", value[0],
                             (unsigned int) ival);

                SSH_PM_MATCH_RADIUS_AVP("tag-integer",
                                        buf, c->pattern);
            }
            else
            {
                SSH_DEBUG(SSH_D_UNCOMMON, ("Invalid tag-integer length %u",
                                           value_len));
                continue;
            }
            break;
        }
    }
    /* FALLTHROUGH */

   out:

    if (conv)
      ssh_charset_free(conv);

    return result;

   success:

    result = true;
    goto out;
}
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

/* Check whether the authentication data `data' matches constraint
   `c'.  The argument `cache' holds cached authentication data, taken
   from `data'. */
static bool
ssh_pm_check_constraint(SshPmAuthData data
                        , SshPmAuthorizationConstraint c
#ifdef SSHDIST_IKE_CERT_AUTH
                        , SshPmAuthDataCache cache
#endif /* SSHDIST_IKE_CERT_AUTH */
                        )
{
#ifdef SSHDIST_IPSEC_XAUTH_SERVER
    SshPmXauthType xauth_type;
    SshRadiusClientRequest radius;
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
    const unsigned char *ber;
    size_t ber_len;
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_IKE_EAP_AUTH
    SshPmAuthMethod auth_method;
#endif /* SSHDIST_IKE_EAP_AUTH */
    SshIkev2PayloadID remote_id = NULL;

    while (c)
    {
        switch (c->type)
        {
          case SSH_PM_CONSTRAIN_PSK_SUBJECT:

            if (data->p1 == NULL)
              break;

            /* Select the remote IKE identity */
            if (data->p1->remote_id)
              remote_id = data->p1->remote_id;
            else if (data->p1->n && data->p1->n->ed)
            {
                if (data->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
                  remote_id = data->p1->n->ed->ike_ed->id_r;
                else
                  remote_id = data->p1->n->ed->ike_ed->id_i;
            }

            if (!remote_id) return false;

            if (!ssh_pm_ikev2_id_compare_pattern(remote_id,
                                                 c->identity_type,
                                                 c->pattern))
              return false;

            break;

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
          case SSH_PM_CONSTRAIN_SUBJECT:
          case SSH_PM_CONSTRAIN_ISSUER:
            if (cache->cert == NULL)
            {
                ber = ssh_pm_auth_get_certificate(data, &ber_len);
                if (ber == NULL)
                {
                    SSH_DEBUG(SSH_D_FAIL, ("No end-user certificate"));
                    return false;
                }

                cache->cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
                if (cache->cert == NULL)
                {
                    SSH_DEBUG(SSH_D_ERROR, ("Could not allocate certificate"));
                    return false;
                }

                if (ssh_x509_cert_decode(ber, ber_len, cache->cert)
                    != SSH_X509_OK)
                {
                    SSH_DEBUG(SSH_D_FAIL,
                              ("Could not decode end-user certificate"));
                    ssh_x509_cert_free(cache->cert);
                    cache->cert = NULL;
                    return false;
                }
            }

            if (!ssh_pm_check_cert_subject(c, cache->cert,
                                           c->type == SSH_PM_CONSTRAIN_SUBJECT
                                           ? true : false))
            {
                SSH_DEBUG(
                        SSH_D_FAIL, ("Certificate constraint did not match"));
                return false;
            }
            break;

          case SSH_PM_CONSTRAIN_CA:
            if (cache->ca_cert == NULL)
            {
                ber = ssh_pm_auth_get_ca_certificate(data, &ber_len);
                if (ber == NULL)
                {
                    SSH_DEBUG(SSH_D_FAIL, ("No CA certificate"));
                    return false;
                }

                cache->ca_cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
                if (cache->ca_cert == NULL)
                {
                    SSH_DEBUG(SSH_D_ERROR, ("Could not allocate certificate"));
                    return false;
                }

                if (ssh_x509_cert_decode(ber, ber_len, cache->ca_cert)
                    != SSH_X509_OK)
                {
                    SSH_DEBUG(SSH_D_FAIL,
                              ("Could not decode CA certificate"));
                    ssh_x509_cert_free(cache->ca_cert);
                    cache->ca_cert = NULL;
                    return false;
                }
            }

            if (!ssh_pm_check_cert_subject(c, cache->ca_cert, true))
            {
                SSH_DEBUG(SSH_D_FAIL, ("CA constraint did not match"));
                return false;
            }

            break;

#else /* SSHDIST_CERT */

























          case SSH_PM_CONSTRAIN_CA:
          case SSH_PM_CONSTRAIN_ISSUER:
          case SSH_PM_CONSTRAIN_SUBJECT:
            break;

#endif /* SSHDIST_CERT */
#else /* SSHDIST_IKE_CERT_AUTH */
          case SSH_PM_CONSTRAIN_CA:
          case SSH_PM_CONSTRAIN_ISSUER:
          case SSH_PM_CONSTRAIN_SUBJECT:
            break;
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
          case SSH_PM_CONSTRAIN_XAUTH:
            xauth_type = ssh_pm_auth_get_xauth_type(data);
            if (xauth_type == SSH_PM_XAUTH_NONE)
              return false;
            break;

          case SSH_PM_CONSTRAIN_XAUTH_RADIUS:
            xauth_type = ssh_pm_auth_get_xauth_type(data);
            if (xauth_type != SSH_PM_XAUTH_RADIUS)
              return false;

            radius = ssh_pm_auth_get_xauth_attributes(data);
            if (radius == NULL)
              return false;

            if (!ssh_pm_check_xauth_radius(c, radius))
            {
                SSH_DEBUG(SSH_D_FAIL, ("RADIUS AVP constraint did not match"));
                return false;
            }
            break;
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

#ifdef SSHDIST_IKE_EAP_AUTH
          case SSH_PM_CONSTRAIN_EAP_SUBJECT:
          {
              /* Do not check if EAP is not yet done. */
              if (data->p1 == NULL || data->p1->n == NULL ||
                  data->p1->n->eap == NULL)
                break;

              /* Select the remote EAP identity */
              if (data->p1->eap_remote_id)
                remote_id = data->p1->eap_remote_id;
              else if (data->p1->n && data->p1->n->ed)
              {
                  if (data->p1->ike_sa->flags &
                      SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
                    remote_id = data->p1->n->ed->ike_ed->id_r;
                  else
                    remote_id = data->p1->n->ed->ike_ed->id_i;
              }

              if (remote_id == NULL) return false;

              if (!ssh_pm_ikev2_id_compare_pattern(remote_id,
                                                   c->identity_type,
                                                   c->pattern))
              {
                  SSH_DEBUG(SSH_D_FAIL, ("Failed to match IKE identity"));
                  return false;
              }
              SSH_DEBUG(SSH_D_MY, ("Successfully matched IKE identity"));
          }
            break;

          case SSH_PM_CONSTRAIN_EAP_AUTH_METHOD:
            /* Ensure that the SA is not IKEv1 */
#ifdef SSHDIST_IKEV1
            if (data->p1 == NULL || data->p1->ike_sa->flags &
                  SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
              break;
#endif /* SSHDIST_IKEV1 */

            if (data->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
              auth_method = data->p1->local_auth_method;
            else
              auth_method = data->p1->remote_auth_method;


            /* If EAP is not yet done, check only the existence
               of any EAP constraints */
            if (data->p1->n && data->p1->n->eap == NULL)
            {
                if (auth_method == SSH_PM_AUTH_PSK
#ifdef SSHDIST_IKE_CERT_AUTH
                    || auth_method == SSH_PM_AUTH_RSA
                    || auth_method == SSH_PM_AUTH_DSA
#ifdef SSHDIST_CRYPT_ECP
                    || auth_method == SSH_PM_AUTH_ECP_DSA
#endif /* SSHDIST_CRYPT_ECP */
#endif /* SSHDIST_IKE_CERT_AUTH */
                    )
                {
                    SSH_DEBUG(SSH_D_FAIL,
                              ("Authentication method did not match "
                               "EAP constraint"));
                    return false;
                }
            }

            /* Check EAP authentication method only after
               EAP negotiation is done. */
            else
            {
                /* Accept any EAP authentication method */
                if (c->auth_method == SSH_PM_AUTH_NONE)
                {
                    if (auth_method != SSH_PM_AUTH_EAP_SIM
                        && auth_method != SSH_PM_AUTH_EAP_AKA



                        && auth_method != SSH_PM_AUTH_EAP_MD5_CHALLENGE



#ifdef SSHDIST_EAP_MSCHAPV2
                        && auth_method != SSH_PM_AUTH_EAP_MSCHAP_V2
#endif /* SSHDIST_EAP_MSCHAPV2 */
                        && auth_method != SSH_PM_AUTH_EAP_TLS
                        )
                    {
                        SSH_DEBUG(SSH_D_FAIL,
                                  ("Authentication method did not match "
                                   "EAP constraint"));
                        return false;
                    }
                }

                /* Accept EAP authentication method specified by constrain */
                else if (auth_method != c->auth_method)
                {
                    SSH_DEBUG(SSH_D_FAIL,
                              ("Authentication method did not match "
                               "EAP constraint"));
                    return false;
                }
            }
            break;
#endif /* SSHDIST_IKE_EAP_AUTH */
        }

        /* This constraint matched.  Check the next one. */
        c = c->next;
    }

    /* Success. */
    return true;
}

void
ssh_pm_authorization_local_callback(SshPmAuthData auth_data,
                                    SshPmAuthorizationResultCB result_cb,
                                    void *result_cb_context,
                                    void *context)
{
    SshPmAuthorizationLocal auth = (SshPmAuthorizationLocal) context;
    SshPmAuthorizationGroup group;
    uint32_t group_ids[32], num_group_ids = 0;
#ifdef SSHDIST_IKE_CERT_AUTH
    SshPmAuthDataCacheStruct cache;

    memset(&cache, 0, sizeof(cache));
#endif /* SSHDIST_IKE_CERT_AUTH */

    /* Check all groups. */
    for (group = auth->groups; group; group = group->next)
    {
        SshPmAuthorizationConstraint c;

        /* Check all constraints. */
        for (c = group->constraints; c; c = c->next)
          if (!ssh_pm_check_constraint(auth_data,
                                       c
#ifdef SSHDIST_IKE_CERT_AUTH
                                       , &cache
#endif /* SSHDIST_IKE_CERT_AUTH */
                                       ))
            break;

        if (c == NULL)
        {
            /* All constraints match. */
            group_ids[num_group_ids++] = group->group_id;
        }

        if (num_group_ids == sizeof(group_ids)/sizeof(group_ids[0]))
        {
            /* break if out of space */
            break;
        }

        /* Continue searching. */
    }

    /* Complete this operation. */
    (*result_cb)(num_group_ids ? group_ids : NULL,
                 num_group_ids,
                 result_cb_context);

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
    /* Clear authentication data cache. */
    if (cache.cert)
      ssh_x509_cert_free(cache.cert);
    if (cache.ca_cert)
      ssh_x509_cert_free(cache.ca_cert);
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
}
