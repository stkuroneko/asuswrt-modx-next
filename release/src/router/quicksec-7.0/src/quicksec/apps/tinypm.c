/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   A simple QuickSec policy manager that uses directly the policy
   management API for policy configuration.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "quicksec_pm.h"
#include "sshglobals.h"

#define SSH_DEBUG_MODULE "tinypm"

/* #define TINYPM_XAUTH */

#ifdef TINYPM_XAUTH

#include "pad_authorization_local.h"

/* Local authorization module. */
SshPmAuthorizationLocal local_auth;
SshPmAuthorizationGroup xauth_group;

#endif /* TINYPM_XAUTH */

/* IKE versions */

/* Default to IKEv2 only */
#undef TINYPM_IKE_VERSIONS

/* Start with IKEv2, allow fallback to IKEv1 */
/* #define TINYPM_IKE_VERSIONS (SSH_PM_IKE_VERSION_1 | SSH_PM_IKE_VERSION_2) */

/* Use IKEv1 only */
/* #define TINYPM_IKE_VERSIONS (SSH_PM_IKE_VERSION_1) */

static SshPm ipm = NULL;


/* Policy manager destroy call-back */
static void stop_cb(void *context)
{
    ipm = NULL;
}

/* Policy configuration call-back */
static void
status_cb(SshPm pm, bool success, void *context)
{
    if (success)
      return;

    ssh_warning("Could not configure rules");

    /* Destory policy manager. */
    ssh_pm_destroy(ipm, stop_cb, NULL);
}

/* Policy manager create call-back */
static void
create_cb(SshPm pm, void *context)
{
    SshPmTunnel tunnel;
    SshPmRule rule;

    if (pm == NULL)
    {
        ssh_warning("Could not connect to the policy manager");
        return;
    }

    ipm = pm;

#ifdef TINYPM_XAUTH
    /* XAUTH with password. */

    SSH_VERIFY(ssh_pm_add_user(pm, "user@somewhere.net",
                               strlen("user@somewhere.net"),
                               SSH_PM_BINARY,
                               "password",
                               strlen("password"),
                               SSH_PM_BINARY));

    /* Create a local authorization module. */
    local_auth = ssh_pm_authorization_local_create();

    /* And configure it to the policy manager. */
    ssh_pm_set_authorization_callback(pm, ssh_pm_authorization_local_callback,
                                      local_auth);


    /* Create a group requiring XAUTH. */
    xauth_group = ssh_pm_authorization_group_create(42);
    SSH_VERIFY(ssh_authorization_group_add_xauth_constraint(
                                                  xauth_group,
                                                  SSH_PM_CONSTRAIN_XAUTH,
                                                  NULL, NULL));

    /* Add group to the authorization module. */
    ssh_pm_authorization_add_group(local_auth, xauth_group);
#endif /* TINYPM_XAUTH */

    /* We are a gateway.

       Host          Plaintext            Gateway          IPSEC       Host
       192.168.10.2 *-------* 192.168.10.2 192.168.11.10 *-------* 192.168.11.1
    */

    /* Create a tunnel object. */
    tunnel = ssh_pm_tunnel_create(ipm,
                                  SSH_PM_CRYPT_3DES | SSH_PM_CRYPT_AES
                                  | SSH_PM_MAC_HMAC_MD5 | SSH_PM_MAC_HMAC_SHA1
                                  | SSH_PM_IPSEC_ESP,
                                  0,
                                  "tunnel");
    if (tunnel == NULL)
    {
        ssh_warning("Could not create tunnel");
        goto error;
    }

    /* Add our IKE peer. */
    if (!ssh_pm_tunnel_add_peer(tunnel, "192.168.11.1"))
    {
        ssh_warning("Could not add IKE peer");
        goto error;
   }

    /* Tunnel identity */
    if (!ssh_pm_tunnel_set_local_identity(tunnel,
                                          0,
                                          SSH_PM_IDENTITY_IP,
                                          SSH_PM_BINARY,
                                          "192.168.11.10",
                                          strlen("192.168.11.10"),
                                          1))
    {
        ssh_warning("Could not configure IKE identity");
        goto error;
    }

    /* Local pre-shared key. */
    if (!ssh_pm_tunnel_set_preshared_key(
                tunnel,
                0,
                SSH_PM_BINARY,
                (unsigned char *) "foo",
                strlen("foo"),
                1))
    {
        ssh_warning("Could not configure local IKE secret");
        goto error;
    }

#ifdef TINYPM_IKE_VERSIONS
    /* IKE versions */
    if (!ssh_pm_tunnel_set_ike_versions(tunnel, TINYPM_IKE_VERSIONS))
    {
        ssh_warning("Could not set IKE versions");
        goto error;
    }
#endif /* TINYPM_IKE_VERSIONS */

    /* Create rule to allow traffic from 192.168.10.2 to 192.168.11.1 */
    rule = ssh_pm_rule_create(ipm, 100, SSH_PM_RULE_PASS, NULL, tunnel);
    if (rule == NULL)
    {
        ssh_warning("Could not create rule from 192.168.10.2 to 192.168.11.1");
        goto error;
    }

    if (!ssh_pm_rule_set_traffic_selector(rule, SSH_PM_FROM,
                                          "ipv4(192.168.10.2)"))
    {
        ssh_warning("Could not set traffic selector");
        goto error;
    }
    if (!ssh_pm_rule_set_traffic_selector(rule, SSH_PM_TO,
                                          "ipv4(192.168.11.1)"))
    {
        ssh_warning("Could not set traffic selector");
        goto error;
    }

#ifdef TINYPM_XAUTH
    /* Require XAUTH on this rule. */
    SSH_VERIFY(ssh_pm_rule_add_authorization_group_id(
                             pm, rule,
                             ssh_pm_authorization_group_get_id(xauth_group)));
#endif /* TINYPM_XAUTH */

    if (ssh_pm_rule_add(ipm, rule) == SSH_IPSEC_INVALID_INDEX)
    {
        ssh_warning("Could not add rule");
        goto error;
    }

    /* Remote pre-shared keys. */
    if (!ssh_pm_add_ike_preshared_key(
                pm,
                NULL,
                SSH_PM_IDENTITY_IP,
                SSH_PM_BINARY,
                "192.168.11.1",
                strlen("192.168.11.1"),
                SSH_PM_BINARY,
                (unsigned char *) "foo",
                strlen("foo")))
    {
        ssh_warning("Could not configure remote IKE secret");
        goto error;
    }

    /* Create rule to allow traffic from 192.168.11.1 to 192.168.10.2 */
    rule = ssh_pm_rule_create(ipm, 100, SSH_PM_RULE_PASS, tunnel, NULL);
    if (rule == NULL)
    {
        ssh_warning("Could not create rule from 192.168.11.1 to 192.168.10.2");
        goto error;
    }

    if (!ssh_pm_rule_set_traffic_selector(rule, SSH_PM_FROM,
                                          "ipv4(192.168.11.1)"))
    {
        ssh_warning("Could not set traffic selector");
        goto error;
    }
    if (!ssh_pm_rule_set_traffic_selector(rule, SSH_PM_TO,
                                          "ipv4(192.168.10.2)"))
    {
        ssh_warning("Could not set traffic selector");
        goto error;
    }

#ifdef TINYPM_XAUTH
    /* Require XAUTH on this rule. */
    SSH_VERIFY(ssh_pm_rule_add_authorization_group_id(
                             pm, rule,
                             ssh_pm_authorization_group_get_id(xauth_group)));
#endif /* TINYPM_XAUTH */


    if (ssh_pm_rule_add(ipm, rule) == SSH_IPSEC_INVALID_INDEX)
    {
        ssh_warning("Could not add rule");
        goto error;
    }

    /* Create a rule to pass everything else in plain-text. */

    rule = ssh_pm_rule_create(ipm, 99, SSH_PM_RULE_PASS, NULL, NULL);
    if (rule == NULL)
    {
        ssh_warning("Could not create rule");
        goto error;
    }

    if (ssh_pm_rule_add(ipm, rule) == SSH_IPSEC_INVALID_INDEX)
    {
        ssh_warning("Could not add rule");
        goto error;
    }

    /* We do not need the tunnel anymore. */
    ssh_pm_tunnel_destroy(pm, tunnel);

    /* Start using our new policy. */
    ssh_pm_commit(ipm, status_cb, NULL);
    return;


    /* Error handling. */

   error:

    /* Free the possibly allocated tunnel object.  The
       ssh_pm_tunnel_destroy() function can be called with NULL argument
       aswell. */
    ssh_pm_tunnel_destroy(pm, tunnel);

    /* Abort possible new rules added to the system.  The ssh_pm_abort()
       function can be called even if we did not add any rules, e.g. the
       current modification batch is empty. */
    ssh_pm_abort(ipm);

    /* Destroy the policy manager.  This will cause the
       ssh_event_loop_run() to return. */
    ssh_pm_destroy(ipm, stop_cb, NULL);
}

/* SIGINT handler for tIpsec */
static void
quit_handler(int sig, void *context)
{
    if (ipm)
      ssh_pm_destroy(ipm, stop_cb, NULL);
}

/* Policy manager */




int
main(int argc, char *argv[])

{
    ssh_global_init();

    /* Allow MACs with zero-length keys.  It is not recommeded to use
       short MAC keys but some example policies use short pre-shared
       keys for IKE. */

    if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    {
        ssh_warning("Could not initialize the crypto library");
        exit(1);
    }

    ssh_event_loop_initialize();

    ssh_pm_library_init();

    ssh_debug_set_level_string("SshPm*=1");

    ssh_register_signal(SIGINT, quit_handler, NULL);

    ssh_pm_create(NULL, create_cb, NULL);

    ssh_event_loop_run();

    ssh_pm_library_uninit();
    ssh_event_loop_uninitialize();
    ssh_crypto_library_uninitialize();
    ssh_debug_uninit();
    ssh_global_uninit();

    return 0;
}
