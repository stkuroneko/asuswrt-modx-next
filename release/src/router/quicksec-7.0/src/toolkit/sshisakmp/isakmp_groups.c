/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp default groups.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshglobals.h"

#define SSH_DEBUG_MODULE "SshIkeGroup"

/* Oakley group description structure. Used to describe the default groups for
   all Diffie-Hellman operations. */
typedef struct SshIkeGroupDescRec {
  SshIkeAttributeGrpDescValues descriptor;
  SshIkeAttributeGrpTypeValues type;
  const char *name;
  uint32_t strength;           /* (modp, ecp, ec2n) optional */
} *SshIkeGroupDesc,SshIkeGroupDescStruct;

struct SshIkeGroupDescRec const ssh_ike_default_group[] = {
  { SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_768,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-ike-grp-modp-768", 0x42, },
  { SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1024,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-ike-grp-modp-1024", 0x4d, },
  { SSH_IKE_VALUES_GRP_DESC_DEFAULT_MODP_1536,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-ike-grp-modp-1536", 0x5b, },
  { 14,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-ike-grp-modp-2048", 110, },
  { 15,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-ike-grp-modp-3072", 130, },
  { 16,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-ike-grp-modp-4096", 150, },
  { 17,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-ike-grp-modp-6144", 170, },
  { 18,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-ike-grp-modp-8192", 190, },
#ifdef SSHDIST_CRYPT_ECP
  { 19, /* ietf-ike-grp-ecp-256 */
    SSH_IKE_VALUES_GRP_TYPE_ECP,
    "prime256v1", 128 },
  { 20, /* ietf-ike-grp-ecp-384 */
    SSH_IKE_VALUES_GRP_TYPE_ECP,
    "secp384r1", 192 },
  { 21, /* ietf-ike-grp-ecp-521 */
    SSH_IKE_VALUES_GRP_TYPE_ECP,
    "secp521r1", 256 },
#endif /* SSHDIST_CRYPT_ECP */
  { 22,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-rfc5114-2-1-modp-1024-160", 80 },
  { 23,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-rfc5114-2-2-modp-2048-224", 112 },
  { 24,
    SSH_IKE_VALUES_GRP_TYPE_MODP,
    "ietf-rfc5114-2-3-modp-2048-256", 112 },
#ifdef SSHDIST_CRYPT_ECP
  { 25, /* ietf-ike-grp-ecp-192, ECP_192 */
    SSH_IKE_VALUES_GRP_TYPE_ECP,
    "secp192r1", 192},
  { 26, /* ietf-ike-grp-ecp-224, ECP_224 */
    SSH_IKE_VALUES_GRP_TYPE_ECP,
    "secp224r1", 224}
#endif /* SSHDIST_CRYPT_ECP */
};

const int ssh_ike_default_group_cnt = sizeof(ssh_ike_default_group) /
  sizeof(ssh_ike_default_group[0]);

SSH_GLOBAL_DEFINE(SshIkeGroupMap *, ssh_ike_groups);

SSH_GLOBAL_DEFINE(int, ssh_ike_groups_count);

SSH_GLOBAL_DECLARE(uint32_t, ssh_ike_groups_alloc_count);
SSH_GLOBAL_DEFINE(uint32_t, ssh_ike_groups_alloc_count);
#define ssh_ike_groups_alloc_count SSH_GLOBAL_USE(ssh_ike_groups_alloc_count)


#ifdef SSHDIST_EXTERNALKEY
/* This callback is called when the acceleration of a group has
 * terminated.
 */
void ssh_ike_get_acc_group_cb(SshEkStatus status,
                              SshPkGroup accelerated_group,
                              void *context)
{
    SshIkeGroupMap gmap = context;
    gmap->accelerator_handle = NULL;
    if (status == SSH_EK_OK)
    {
        /* We got the accelerated group. Swap the groups so that all the
           subsequent operations use this accelerated group. */
        SshPkGroup group;

        SSH_DEBUG(SSH_D_LOWOK, ("Received accelerator group. "));
        group = gmap->group;
        gmap->group = accelerated_group;
        gmap->old_group = group;
      }
    else
    {
        /* We did not manage to accelerate a group using the
           EK. Continue using the software group. */
        SSH_DEBUG(SSH_D_LOWOK, ("Could not accelerate the group."));
    }
}

#endif /* SSHDIST_EXTERNALKEY */
/*                                                              shade{0.9}
 * Add new group to group table. Return true if successful.    shade{1.0}
 */
bool ike_add_default_group(SshIkeContext isakmp_context, int descriptor,
                              SshPkGroup group)
{
    if (ssh_ike_groups_alloc_count == ssh_ike_groups_count)
    {
        if (ssh_ike_groups_alloc_count == 0)
        {
            ssh_ike_groups_alloc_count = 10;
            ssh_ike_groups = ssh_calloc(ssh_ike_groups_alloc_count,
                                        sizeof(SshIkeGroupMap));
            if (ssh_ike_groups == NULL)
              return false;
        }
        else
        {
            if (!ssh_recalloc(&ssh_ike_groups,
                              &ssh_ike_groups_alloc_count,
                              ssh_ike_groups_alloc_count + 10,
                              sizeof(SshIkeGroupMap)))
              return false;
        }
    }
    ssh_ike_groups[ssh_ike_groups_count] =
      ssh_calloc(1, sizeof(struct SshIkeGroupMapRec));
    if (ssh_ike_groups[ssh_ike_groups_count] == NULL)
      return false;
    ssh_ike_groups[ssh_ike_groups_count]->isakmp_context = isakmp_context;
    ssh_ike_groups[ssh_ike_groups_count]->descriptor = descriptor;
    ssh_ike_groups[ssh_ike_groups_count]->group = group;
#ifdef SSHDIST_EXTERNALKEY
    /* Try fetching the accelerated group, if we have accelerators defined. */
    if (isakmp_context->external_key && isakmp_context->accelerator_short_name)
    {
        SshOperationHandle handle;
        SshIkeGroupMap gmap = ssh_ike_groups[ssh_ike_groups_count];

        handle =
          ssh_ek_generate_accelerated_group(isakmp_context->external_key,
                                            isakmp_context->
                                            accelerator_short_name,
                                            group,
                                            ssh_ike_get_acc_group_cb,
                                            gmap);
        if (handle)
          gmap->accelerator_handle = handle;
    }
#endif /* SSHDIST_EXTERNALKEY */
    ssh_ike_groups_count++;
    return true;
}

/*                                                              shade{0.9}
 * Uninitialize default group data                              shade{1.0}
 */
void ike_default_groups_uninit(SshIkeContext isakmp_context)
{
    int i;
    for (i = 0; i < ssh_ike_groups_count; i++)
    {
        ssh_pk_group_free(ssh_ike_groups[i]->group);
#ifdef SSHDIST_EXTERNALKEY
        if (ssh_ike_groups[i]->old_group)
          ssh_pk_group_free(ssh_ike_groups[i]->old_group);
        ssh_operation_abort(ssh_ike_groups[i]->accelerator_handle);
#endif /* SSHDIST_EXTERNALKEY */
        ssh_cancel_timeouts(SSH_ALL_CALLBACKS, ssh_ike_groups[i]);
        ssh_ike_groups[i]->group = NULL;
        ssh_free(ssh_ike_groups[i]);
        ssh_ike_groups[i] = NULL;
    }
    ssh_free(ssh_ike_groups);
    ssh_ike_groups = NULL;
    ssh_ike_groups_count = 0;
    ssh_ike_groups_alloc_count = 0;
}

/*                                                              shade{0.9}
 * Initialize default group data                                shade{1.0}
 */
bool ike_default_groups_init(SshIkeContext isakmp_context)
{
    int i;
    const SshIkeGroupDescStruct* grp;
    SshPkGroup pk_grp;
    SshCryptoStatus cret;

    SSH_GLOBAL_INIT(ssh_ike_groups, NULL);
    SSH_GLOBAL_INIT(ssh_ike_groups_count, 0);
    SSH_GLOBAL_INIT(ssh_ike_groups_alloc_count, 0);

    for (i = 0; i < ssh_ike_default_group_cnt; i++)
    {
        grp = &(ssh_ike_default_group[i]);

        switch (grp->type)
        {
          case SSH_IKE_VALUES_GRP_TYPE_MODP:
            cret =
                ssh_pk_group_generate(
                        &pk_grp,
                        "dl-modp",
                        SSH_PKF_PREDEFINED_GROUP, grp->name,
                        SSH_PKF_DH, "plain",
                        SSH_PKF_RANDOMIZER_ENTROPY,
                        (unsigned int) ((grp->strength * 5)>>1),
                        SSH_PKF_END);
            break;

          case SSH_IKE_VALUES_GRP_TYPE_EC2N:
            cret = SSH_CRYPTO_UNSUPPORTED;
            break;
          case SSH_IKE_VALUES_GRP_TYPE_ECP:
#ifdef SSHDIST_CRYPT_ECP
            cret = ssh_pk_group_generate(&pk_grp,
                                         "ec-modp",
                                         SSH_PKF_PREDEFINED_GROUP, grp->name,
                                         SSH_PKF_DH, "plain",
                                         SSH_PKF_END);
#else /* SSHDIST_CRYPT_ECP */
            cret = SSH_CRYPTO_UNSUPPORTED;
#endif /* SSHDIST_CRYPT_ECP  */
            break;
          default:
            cret = SSH_CRYPTO_UNSUPPORTED;
            break;
        }

        if (cret == SSH_CRYPTO_OK)
        {
            if (!ike_add_default_group(
                        isakmp_context, grp->descriptor, pk_grp))
            {
                ssh_pk_group_free(pk_grp);
                return false;
            }
        }
        else
        {
            return false;
        }
    }
    return true;
}
