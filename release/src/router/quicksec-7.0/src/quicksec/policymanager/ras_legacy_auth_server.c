/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   High-level legacy authentication server functionality.  This uses
   the low-level functions and callbacks, defined in the
   `vpm_pm_low.h' API.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmLegacyAuthServer"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

/********************** Legacy authentication methods ***********************/

#ifdef SSHDIST_RADIUS
bool
ssh_pm_set_radius_servers(SshPm pm,
                          SshPmAuthDomain ad,
                          SshRadiusClient client,
                          SshRadiusClientServerInfo servers)
{
    if (ad->radius_auth  || ad->passwd_auth)
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("Radius client or user information already configured "
                   "while setting radius client for this auth domain"));
        return false;
    }

    ad->radius_auth = ssh_pm_auth_radius_create(client, servers);
    if (ad->radius_auth == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Could not create XAUTH radius object"));
        return false;
    }

    /* Store RADIUS client and server info for later reuse with other
       remote access methods (L2TP). */
    ad->radius_client = client;
    ad->radius_server_info = servers;

    ssh_pm_set_auth_radius(pm, ad->radius_auth);

#ifdef SSHDIST_IKE_XAUTH
    ad->passwd_auth = ssh_pm_auth_passwd_create();
    if (ad->passwd_auth != NULL)
    {
        ssh_pm_set_auth_passwd(pm, ad->passwd_auth);
        ssh_pm_set_auth_passwd_radius(pm, ad->passwd_auth, client, servers);
    }
#endif /* SSHDIST_IKE_XAUTH */

    return true;
}
#endif /* SSHDIST_RADIUS */

bool
ssh_pm_add_user(SshPm pm,
                SshPmAuthDomain ad,
                const char *user_name,
                size_t user_name_len,
                SshPmSecretEncoding user_name_encoding,
                const char *password,
                size_t password_len,
                SshPmSecretEncoding password_encoding)
{
    unsigned char *decoded_user, *decoded_password;
    bool ret, malformed;
    size_t len_user_return, len_pass_return;

#ifdef SSHDIST_RADIUS
    if (ad->radius_auth)
    {
        SSH_DEBUG(SSH_D_ERROR,
                  ("Radius client already set when adding local user"));
        return false;
    }
#endif /* SSHDIST_RADIUS */

    if (ad->passwd_auth == NULL)
    {
        ad->passwd_auth = ssh_pm_auth_passwd_create();
        if (ad->passwd_auth == NULL)
        {
            SSH_DEBUG(SSH_D_ERROR, ("Could not create XAUTH passwd object"));
            return false;
        }

        ssh_pm_set_auth_passwd(pm, ad->passwd_auth);
    }

    /* Add new user to our password module. */
    decoded_user = ssh_pm_decode_secret(user_name_encoding,
                                        (unsigned char *) user_name,
                                        user_name_len,
                                        &len_user_return,
                                        &malformed);
    if (decoded_user == NULL)
    {
        if (malformed)
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Malformed encoding on username: %s",
                        user_name);
        return false;
    }

    decoded_password = ssh_pm_decode_secret(password_encoding,
                                            (unsigned char *) password,
                                            password_len,
                                            &len_pass_return,
                                            &malformed);
    if (decoded_password == NULL)
    {
        ssh_free(decoded_user);
        if (malformed)
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Malformed encoding on password: %s",
                        password);
        return false;
    }
    ret = ssh_pm_auth_passwd_add(ad->passwd_auth, decoded_user,
                                 len_user_return,
                                 decoded_password, len_pass_return);
    ssh_free(decoded_password);
    ssh_free(decoded_user);
    return ret;
}


bool
ssh_pm_remove_user(SshPm pm,
                   SshPmAuthDomain ad,
                   const unsigned char *user_name,
                   size_t user_name_len,
                   SshPmSecretEncoding user_name_encoding)
{
    unsigned char *decoded_user;
    bool ret, malformed;
    size_t len_return;

#ifdef SSHDIST_RADIUS
    SSH_ASSERT(ad->radius_auth == NULL);
#endif /* SSHDIST_RADIUS */

    if (ad->passwd_auth == NULL)
      return false;

    decoded_user = ssh_pm_decode_secret(user_name_encoding,
                                        user_name,
                                        user_name_len,
                                        &len_return,
                                        &malformed);
    if (decoded_user == NULL)
    {
        if (malformed)
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Malformed encoding on username: %s",
                        user_name);
        return false;
    }
    ret = ssh_pm_auth_passwd_remove(ad->passwd_auth, decoded_user,
                                    len_return);
    ssh_free(decoded_user);
    return ret;
}


#ifdef SSHDIST_IPSEC_XAUTH_SERVER
bool
ssh_pm_set_xauth_method(SshPm pm,
                        SshIkeXauthType method,
                        SshPmXauthFlags flags)
{
    ssh_pm_xauth_method(pm, method, flags);

    return true;
}

#endif /* SSHDIST_IPSEC_XAUTH_SERVER */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
