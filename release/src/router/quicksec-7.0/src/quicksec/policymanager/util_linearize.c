/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Linearizing IKE and IPsec SAs and the reverse - installing them back.
*/

#include "sshincludes.h"
#include "sshadt.h"
#include "quicksecpm_internal.h"
#include "sshikev2-util.h"
#include "ipsec_sa_params.h"

#define SSH_DEBUG_MODULE "SshPmLinearize"


#ifdef SSHDIST_IPSEC_SA_EXPORT

/************************** Types and definitions ***************************/

/** Encoding format version:
    Ver 1: Original format after rewrite.
    Ver 2: Tunnel, outer tunnel and rule application identifiers and transform
           interface name were added, transform data encoding was fixed.
*/

#define SSH_PM_SA_EXPORT_VERSION             0x00000002

/** Type of encoded buffer. */
#define SSH_PM_SA_EXPORT_IKE_SA              0x00000001
#define SSH_PM_SA_EXPORT_IPSEC_SA            0x00000002
#define SSH_PM_SA_EXPORT_IKE_SA_DESTROYED    0x00000004
#define SSH_PM_SA_EXPORT_IPSEC_SA_DESTROYED  0x00000008


static bool
pm_ipsec_sa_params_get_spis(
        struct IPsecSaParams* ipsec_sa_params,
        uint32_t *inbound_spi_p,
        uint32_t *outbound_spi_p,
        SshInetIPProtocolID *ipproto_p)
{
    bool ok = false;

    if (ipsec_sa_params->ipproto == SSH_IPPROTO_ESP ||
        ipsec_sa_params->ipproto == SSH_IPPROTO_AH)
    {
        *inbound_spi_p = ipsec_sa_params->inbound_spi;
        *outbound_spi_p = ipsec_sa_params->outbound_spi;
        *ipproto_p = ipsec_sa_params->ipproto;

        ok = true;
    }

    return ok;
}

/***************************** Rendering SPI values **************************/
#ifdef DEBUG_LIGHT
static int pm_ipsec_spi_render(char *buf, int buf_size,
                               int precision, void *datum)
{
    SshPmQm qm = datum;
    int len;

    if (qm == NULL)
    {
        len = ssh_snprintf(buf, buf_size + 1, "(null)");
    }
    else
    {
        uint32_t inbound_spi;
        uint32_t outbound_spi;
        SshInetIPProtocolID ipproto;
        bool ok;

        SSH_PM_ASSERT_QM(qm);

        ok =
            pm_ipsec_sa_params_get_spis(
                    &qm->ipsec_sa_params,
                    &inbound_spi,
                    &outbound_spi,
                    &ipproto);

        if (ok == false)
        {
            len = ssh_snprintf(buf, buf_size + 1, "unknown-protocol-0");
        }
        else
        {
            len =
                ssh_snprintf(
                        buf, buf_size + 1,
                        "%s-%08lx",
                        (ipproto == SSH_IPPROTO_ESP ? "ESP" : "AH"),
                        inbound_spi);
        }
    }

    if (len >= buf_size)
      return buf_size + 1;
    return len;
}

static int pm_ike_spi_render(char *buf, int buf_size,
                             int precision, void *datum)
{
    unsigned char *ike_spi = datum;
    int len;

    if (ike_spi == NULL)
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
    else
      len =
          ssh_snprintf(
                  buf,
                  buf_size + 1,
                  "%02x%02x%02x%02x %02x%02x%02x%02x",
                  ike_spi[0], ike_spi[1], ike_spi[2], ike_spi[3],
                  ike_spi[4], ike_spi[5], ike_spi[6], ike_spi[7]);

    if (len >= buf_size)
      return buf_size + 1;
    return len;
}
#endif /* DEBUG_LIGHT */
/***************************** Encoding Identities ***************************/

static unsigned char *
pm_util_encode_id(SshIkev2PayloadID id, size_t *id_len_ret)
{
    unsigned char *id_ret;
    size_t len;

    if (id == NULL)
    {
        *id_len_ret = 0;
        return NULL;
    }

    switch (id->id_type)
    {
      case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
        len = 4;
        break;
      case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
        len = 16;
        break;
      default:
        len = id->id_data_size;
        break;
    }

    *id_len_ret =
      ssh_encode_array_alloc(&id_ret,
                             SSH_ENCODE_CHAR((unsigned int) id->id_type),
                             SSH_ENCODE_UINT32_STR(id->id_data, len),
                             SSH_FORMAT_END);

    return id_ret;
}

static SshIkev2PayloadID
pm_util_decode_id(unsigned char *data, size_t data_len)
{
    SshIkev2PayloadID id;
    size_t len;

    if (data_len == 0)
      return NULL;

    id = ssh_calloc(1, sizeof(*id));
    if (id == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate memory for identity data"));
        return NULL;
    }

    len =
      ssh_decode_array(data, data_len,
                       SSH_DECODE_CHAR((unsigned int *)&id->id_type),
                       SSH_DECODE_UINT32_STR(&id->id_data, &id->id_data_size),
                       SSH_FORMAT_END);

    if (len != data_len)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Encoded identity %@ has %d bytes trailing garbage",
                   ssh_pm_ike_id_render, id, data_len - len));
        ssh_free(id);
        return NULL;
    }

    SSH_DEBUG(SSH_D_MIDOK, ("Decoded ID %@", ssh_pm_ike_id_render, id));
    return id;
}

/***************************** Encoding remote access attributes *************/

#ifdef SSHDIST_ISAKMP_CFG_MODE
static unsigned char *
pm_util_encode_ras_attrs(SshPmRemoteAccessAttrs ras_attrs,
                         size_t *encoded_ras_attrs_len)
{
    SshBufferStruct buffer[1];
    uint32_t i;
    size_t len;
    unsigned char *encoded_ras_attrs = NULL;

    SSH_ASSERT(encoded_ras_attrs_len != NULL);

    if (ras_attrs == NULL)
    {
        *encoded_ras_attrs_len = 0;
        return NULL;
    }

    ssh_buffer_init(buffer);

    /* Encode RAS addresses. */
    if (ras_attrs->address_expiry_set)
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_UINT32(ras_attrs->address_expiry),
                              SSH_FORMAT_END);
    else
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_UINT32(0),
                              SSH_FORMAT_END);
    if (len != 4)
      goto error;

    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32(ras_attrs->num_addresses),
                            SSH_FORMAT_END);
    if (len != 4)
      goto error;

    for (i = 0; i < ras_attrs->num_addresses; i++)
    {
        len = ssh_encode_buffer(buffer,
                                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                                   &ras_attrs->addresses[i]),
                                SSH_FORMAT_END);
        if (len == 0)
          goto error;
    }

    /* Encode DHCP server DUID */
    if (ras_attrs->server_duid_len > 0)
    {
        len = ssh_encode_buffer(buffer,
                                SSH_ENCODE_UINT16(ras_attrs->server_duid_len),
                                SSH_FORMAT_END);
        if (len != 2)
          goto error;

        len = ssh_encode_buffer(buffer,
                                SSH_ENCODE_DATA(ras_attrs->server_duid,
                                                ras_attrs->server_duid_len),
                                SSH_FORMAT_END);
        if (len == 0)
          goto error;
    }
    else
    {
        len = ssh_encode_buffer(buffer,
                                SSH_ENCODE_UINT16((uint16_t)0),
                                SSH_FORMAT_END);
        if (len != 2)
          goto error;
    }

    /* Encode DNS addresses. */
    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32(ras_attrs->num_dns),
                            SSH_FORMAT_END);
    if (len != 4)
      goto error;

    for (i = 0; i < ras_attrs->num_dns; i++)
    {
        len = ssh_encode_buffer(buffer,
                                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                                   &ras_attrs->dns[i]),
                                SSH_FORMAT_END);
        if (len == 0)
          goto error;
    }

    /* Encode WINS addresses. */
    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32(ras_attrs->num_wins),
                            SSH_FORMAT_END);
    if (len != 4)
      goto error;

    for (i = 0; i < ras_attrs->num_wins; i++)
    {
        len = ssh_encode_buffer(buffer,
                                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                                   &ras_attrs->wins[i]),
                                SSH_FORMAT_END);
        if (len == 0)
          goto error;
    }

    /* Encode DHCP addresses. */
    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32(ras_attrs->num_dhcp),
                            SSH_FORMAT_END);
    if (len != 4)
      goto error;

    for (i = 0; i < ras_attrs->num_dhcp; i++)
    {
        len = ssh_encode_buffer(buffer,
                                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                                   &ras_attrs->dhcp[i]),
                                SSH_FORMAT_END);
        if (len == 0)
          goto error;
    }

    /* Encode subnets. */
    len =
      ssh_encode_buffer(buffer,
                        SSH_ENCODE_UINT32(ras_attrs->num_subnets),
                        SSH_FORMAT_END);
    if (len != 4)
      goto error;

    for (i = 0; i < ras_attrs->num_subnets; i++)
    {
        len = ssh_encode_buffer(buffer,
                                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                                   &ras_attrs->subnets[i]),
                                SSH_FORMAT_END);
        if (len == 0)
          goto error;
    }

    encoded_ras_attrs = ssh_buffer_steal(buffer, encoded_ras_attrs_len);
    ssh_buffer_uninit(buffer);
    return encoded_ras_attrs;

   error:
    *encoded_ras_attrs_len = 0;
    return NULL;
}


static bool
pm_util_decode_p1_ras_attrs(const unsigned char *buf,
                            size_t buf_len,
                            SshPmRemoteAccessAttrs ras_attrs)
{
    size_t len, offset;
    uint32_t i;
    uint32_t num_addresses;

    SSH_ASSERT(ras_attrs != NULL);

    /* Decode RAS addresses. */
    len =
      ssh_decode_array(buf, buf_len,
                       SSH_DECODE_UINT32(&ras_attrs->address_expiry),
                       SSH_DECODE_UINT32(&num_addresses),
                       SSH_FORMAT_END);
    if (len != 8 ||
        (num_addresses > SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES))
      goto error;
    offset = len;

    if (ras_attrs->address_expiry > 0)
      ras_attrs->address_expiry_set = true;

    ras_attrs->num_addresses = num_addresses;

    for (i = 0; i < ras_attrs->num_addresses; i++)
    {
        len = ssh_decode_array(buf + offset, buf_len - offset,
                               SSH_DECODE_SPECIAL_NOALLOC(
                               ssh_decode_ipaddr_array,
                               &ras_attrs->addresses[i]),
                               SSH_FORMAT_END);
        if (len == 0)
          goto error;

        offset += len;
    }

    /* Decode DHCP server DUID */
    len =
      ssh_decode_array(buf +  offset, buf_len - offset,
                       SSH_DECODE_UINT16(&ras_attrs->server_duid_len),
                       SSH_FORMAT_END);
    offset += len;

    if (ras_attrs->server_duid_len > 0)
    {
        ras_attrs->server_duid = ssh_calloc(1, ras_attrs->server_duid_len);
        if (ras_attrs->server_duid == NULL)
          goto error;

        len =
            ssh_decode_array(
                    buf + offset, buf_len - offset,
                    SSH_DECODE_DATA(ras_attrs->server_duid,
                                    (size_t)ras_attrs->server_duid_len),
                    SSH_FORMAT_END);
        if (len == 0)
          goto error;

        offset += len;
    }
    else
    {
        ras_attrs->server_duid = NULL;
    }

    /* Decode DNS addresses. */
    len = ssh_decode_array(buf + offset, buf_len - offset,
                           SSH_DECODE_UINT32(&ras_attrs->num_dns),
                           SSH_FORMAT_END);
    if (len != 4
        || (ras_attrs->num_dns > SSH_PM_REMOTE_ACCESS_NUM_SERVERS))
      goto error;
    offset += len;

    for (i = 0; i < ras_attrs->num_dns; i++)
    {
        len = ssh_decode_array(buf + offset, buf_len - offset,
                               SSH_DECODE_SPECIAL_NOALLOC(
                               ssh_decode_ipaddr_array,
                               &ras_attrs->dns[i]),
                               SSH_FORMAT_END);
        if (len == 0)
          goto error;

        offset += len;
    }

    /* Decode WINS addresses. */
    len = ssh_decode_array(buf + offset, buf_len - offset,
                           SSH_DECODE_UINT32(&ras_attrs->num_wins),
                           SSH_FORMAT_END);
    if (len != 4
        || (ras_attrs->num_wins > SSH_PM_REMOTE_ACCESS_NUM_SERVERS))
      goto error;
    offset += len;

    for (i = 0; i < ras_attrs->num_wins; i++)
    {
        len = ssh_decode_array(buf + offset, buf_len - offset,
                               SSH_DECODE_SPECIAL_NOALLOC(
                               ssh_decode_ipaddr_array,
                               &ras_attrs->wins[i]),
                               SSH_FORMAT_END);
        if (len == 0)
          goto error;

        offset += len;
    }

    /* Decode DHCP addresses. */
    len = ssh_decode_array(buf + offset, buf_len - offset,
                           SSH_DECODE_UINT32(&ras_attrs->num_dhcp),
                           SSH_FORMAT_END);
    if (len != 4
        || (ras_attrs->num_dhcp > SSH_PM_REMOTE_ACCESS_NUM_SERVERS))
      goto error;
    offset += len;

    for (i = 0; i < ras_attrs->num_dhcp; i++)
    {
        len = ssh_decode_array(buf + offset, buf_len - offset,
                               SSH_DECODE_SPECIAL_NOALLOC(
                               ssh_decode_ipaddr_array,
                               &ras_attrs->dhcp[i]),
                               SSH_FORMAT_END);
        if (len == 0)
          goto error;

        offset += len;
    }

    /* Decode subnets. */
    len = ssh_decode_array(buf + offset, buf_len - offset,
                           SSH_DECODE_UINT32(&ras_attrs->num_subnets),
                           SSH_FORMAT_END);
    if (len != 4
        || (ras_attrs->num_subnets > SSH_PM_REMOTE_ACCESS_NUM_SUBNETS))
      goto error;
    offset += len;

    for (i = 0; i < ras_attrs->num_subnets; i++)
    {
        len = ssh_decode_array(buf + offset, buf_len - offset,
                               SSH_DECODE_SPECIAL_NOALLOC(
                               ssh_decode_ipaddr_array,
                               &ras_attrs->subnets[i]),
                               SSH_FORMAT_END);
        if (len == 0)
          goto error;

        offset += len;
    }

    /* Check that decoding consumed all data. */
    if (offset != buf_len)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Encoded RAS attribute has %d trailing garbage",
                               buf_len - offset));
        goto error;
    }

    return true;

   error:
    if (ras_attrs->server_duid != NULL)
      ssh_free(ras_attrs->server_duid);
    ras_attrs->server_duid = NULL;
    ras_attrs->server_duid_len = 0;

    SSH_DEBUG(SSH_D_FAIL, ("RAS attribute decode failed"));
    return false;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/***************************** Public functions *****************************/

/* Perform housekeeping tasks after all IKE and IPSec SAs have been
   imported. */
void
ssh_pm_import_finalize(SshPm pm)
{

    SSH_APE_MARK(1, ("SA import done"));
}


/***************************** IKE SA export *********************************/


static size_t
pm_ike_sa_encode_deleted_event(SshPm pm,
                               SshPmIkeSAEventHandle ike_sa,
                               SshBuffer buffer)
{
    size_t total_len;
    uint32_t ike_version = 2;

#ifdef SSHDIST_IKEV1
    if (ike_sa->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
      ike_version = 1;
#endif /* SSHDIST_IKEV1 */

    /* Encode fixed IPsec SA export header, IP protocol and SPI values. */
    total_len =
      ssh_encode_buffer(buffer,
                        SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_VERSION),
                        SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_IKE_SA_DESTROYED),
                        SSH_ENCODE_UINT32(ike_version),
                        SSH_ENCODE_DATA(ike_sa->p1->ike_sa->ike_spi_i,
                                        (size_t) 8),
                        SSH_ENCODE_DATA(ike_sa->p1->ike_sa->ike_spi_r,
                                        (size_t) 8),
                        SSH_FORMAT_END);
    if (total_len == 0)
      goto encode_error;

    SSH_DEBUG(SSH_D_LOWOK, ("IKEv%d SA %@ destroyed event encoded",
                            ike_version,
                            ssh_ikev2_ike_spi_render, ike_sa->p1->ike_sa));

    return total_len;

   encode_error:
    SSH_DEBUG(SSH_D_FAIL, ("IKEv%d SA %@ destroyed event encode failed",
                           ike_version,
                           ssh_ikev2_ike_spi_render, ike_sa->p1->ike_sa));
    return 0;
}


/* Flag values for IKE SA import_flags. */
#define SSH_PM_IKE_SA_IMPORT_FLAG_RAS                    0x0001
#define SSH_PM_IKE_SA_IMPORT_FLAG_RAC                    0x0002
#define SSH_PM_IKE_SA_IMPORT_FLAG_REKEYED                0x0004
#define SSH_PM_IKE_SA_IMPORT_FLAG_AUTH_GROUP_IDS_SET     0x0008
#define SSH_PM_IKE_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK 0x0010

size_t
ssh_pm_ike_sa_export(SshPm pm, SshPmIkeSAEventHandle ike_sa, SshBuffer buffer)
{
    SshPmP1 p1;
    unsigned char *encoded_ike_sa = NULL;
    size_t encoded_ike_sa_len = 0;
    unsigned char *local_id = NULL;
    size_t local_id_len = 0;
    unsigned char *remote_id = NULL;
    size_t remote_id_len = 0;
    unsigned char *second_local_id = NULL;
    size_t second_local_id_len = 0;
    unsigned char *second_remote_id = NULL;
    size_t second_remote_id_len = 0;
    SshPmAuthMethod second_local_auth_method = SSH_PM_AUTH_NONE;
    SshPmAuthMethod second_remote_auth_method = SSH_PM_AUTH_NONE;
    unsigned char *eap_remote_id = NULL;
    size_t eap_remote_id_len = 0;
    unsigned char *second_eap_remote_id = NULL;
    size_t second_eap_remote_id_len = 0;
    unsigned char *ras_attrs = NULL;
    size_t ras_attrs_len = 0;
    size_t len, total_len = 0;
    uint32_t i;
    uint16_t local_port;
    uint32_t import_flags = 0;
    SshPmTunnel tunnel;
    char *tunnel_app_id;
    size_t tunnel_app_id_len = 0;

    /* Check input parameters. */
    if (ike_sa == NULL || buffer == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
        return 0;
    }

    if (ike_sa->event == SSH_PM_SA_EVENT_DELETED)
      return pm_ike_sa_encode_deleted_event(pm, ike_sa, buffer);

    p1 = ike_sa->p1;

    /* Do not export failed, not-yet-done and unusable IKE SAs, except
       allow export of rekeyed IKE SA (which is always unusable when
       exported). */
    if (p1->failed || !p1->done || (p1->unusable && !p1->rekeyed))
    {
        SSH_DEBUG(SSH_D_FAIL, ("Cannot export unusable IKE SA"));
        return 0;
    }

    if (p1->rekeyed)
      import_flags |= SSH_PM_IKE_SA_IMPORT_FLAG_REKEYED;

    if (p1->auth_group_ids_set)
      import_flags |= SSH_PM_IKE_SA_IMPORT_FLAG_AUTH_GROUP_IDS_SET;

    /* Encode identities. */
    remote_id = pm_util_encode_id(p1->remote_id, &remote_id_len);
    if (p1->remote_id && remote_id == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE remote identity encode failed"));
        goto error;
    }
    local_id = pm_util_encode_id(p1->local_id, &local_id_len);
    if (p1->local_id && local_id == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE local identity encode failed"));
        goto error;
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
    second_remote_id = pm_util_encode_id(p1->second_remote_id,
                                         &second_remote_id_len);
    if (p1->second_remote_id && second_remote_id == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE second remote identity encode failed"));
        goto error;
    }
    second_local_id = pm_util_encode_id(p1->second_local_id,
                                        &second_local_id_len);
    if (p1->second_local_id && second_local_id == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE second local identity encode failed"));
        goto error;
    }
    second_local_auth_method = p1->second_local_auth_method;
    second_remote_auth_method = p1->second_remote_auth_method;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

#ifdef SSHDIST_IKE_EAP_AUTH
    eap_remote_id = pm_util_encode_id(p1->eap_remote_id, &eap_remote_id_len);
    if (p1->eap_remote_id && eap_remote_id == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE EAP remote identity encode failed"));
        goto error;
    }
#ifdef SSH_IKEV2_MULTIPLE_AUTH
    second_eap_remote_id = pm_util_encode_id(p1->second_eap_remote_id,
                                             &second_eap_remote_id_len);
    if (p1->second_eap_remote_id && second_eap_remote_id == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("IKE second EAP remote identity encode failed"));
        goto error;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
    if (p1->enable_blacklist_check)
      import_flags |= SSH_PM_IKE_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK;
#endif /* SSH_PM_BLACKLIST_ENABLED */

#ifdef SSHDIST_ISAKMP_CFG_MODE
    /* Encode RAS attributes. */
    if (p1->remote_access_attrs)
    {
        ras_attrs = pm_util_encode_ras_attrs(p1->remote_access_attrs,
                                             &ras_attrs_len);
        if (ras_attrs == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("IKE RAS attribute encode failed"));
            goto error;
        }
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
        if (p1->cfgmode_client)
          import_flags |= SSH_PM_IKE_SA_IMPORT_FLAG_RAS;
        else
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
          import_flags |= SSH_PM_IKE_SA_IMPORT_FLAG_RAC;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */

    tunnel = ssh_pm_tunnel_get_by_id(pm, p1->tunnel_id);
    if (tunnel == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA tunnel_id %d",
                               (int) p1->tunnel_id));
        goto error;
    }
    tunnel_app_id = tunnel->application_identifier;
    tunnel_app_id_len = tunnel->application_identifier_len;

    /* Encode the ikev2 library part of IKE SA. */
    if (ssh_ikev2_encode_sa(p1->ike_sa, &encoded_ike_sa, &encoded_ike_sa_len)
        != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
        goto error;
    }

    /* Encode fixed IKE SA export header to export buffer. */
    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_VERSION),
                            SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_IKE_SA),
                            SSH_FORMAT_END);
    if (len == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA export header encode failed"));
        goto error;
    }
    total_len = len;

    /* Encode p1 body to export buffer. */
    local_port = SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa);
    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                   p1->ike_sa->remote_ip),
                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                   &p1->ike_sa->server->ip_address),
                SSH_ENCODE_UINT16(local_port),
                SSH_ENCODE_UINT64((uint64_t)
                                  ssh_time_from_monotonic_time(
                                          p1->expire_time)),
                SSH_ENCODE_UINT64(p1->lifetime),
                SSH_ENCODE_UINT16(p1->dh_group),
                SSH_ENCODE_UINT16(p1->local_auth_method),
                SSH_ENCODE_UINT16(p1->remote_auth_method),
                SSH_ENCODE_UINT32_STR(local_id, local_id_len),
                SSH_ENCODE_UINT32_STR(remote_id, remote_id_len),
                SSH_ENCODE_UINT16(second_local_auth_method),
                SSH_ENCODE_UINT16(second_remote_auth_method),
                SSH_ENCODE_UINT32_STR(second_local_id,
                                      second_local_id_len),
                SSH_ENCODE_UINT32_STR(second_remote_id,
                                      second_remote_id_len),
                SSH_ENCODE_UINT32_STR(eap_remote_id,
                                      eap_remote_id_len),
                SSH_ENCODE_UINT32_STR(second_eap_remote_id,
                                      second_eap_remote_id_len),
                SSH_ENCODE_UINT32_STR(p1->local_secret,
                                      p1->local_secret_len),
                SSH_ENCODE_UINT32(p1->compat_flags),
                SSH_ENCODE_UINT32(p1->tunnel_id),
                SSH_ENCODE_UINT32_STR(p1->old_ike_spi_i, 8),
                SSH_ENCODE_UINT32_STR(p1->old_ike_spi_r, 8),
                SSH_ENCODE_UINT32(import_flags),
                SSH_ENCODE_UINT32_STR(
                        (unsigned char *) tunnel_app_id,
                        tunnel_app_id_len),
                SSH_FORMAT_END);
    if (len == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
        goto error;
    }
    total_len += len;

    /* Encode authorization group ids to export buffer. */
    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32(p1->num_authorization_group_ids),
                            SSH_FORMAT_END);
    if (len != 4)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
        goto error;
    }
    total_len += len;

    for (i = 0; i < p1->num_authorization_group_ids; i++)
    {
        SSH_ASSERT(p1->auth_group_ids_set);

        len =
          ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32(p1->authorization_group_ids[i]),
                            SSH_FORMAT_END);
        if (len != 4)
        {
            SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
            goto error;
        }
        total_len += len;
    }

    /* Encode XAUTH authorization group ids to export buffer. */
    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_UINT32(p1->num_xauth_authorization_group_ids),
                SSH_FORMAT_END);
    if (len != 4)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
        goto error;
    }
    total_len += len;

    for (i = 0; i < p1->num_xauth_authorization_group_ids; i++)
    {
        len =
            ssh_encode_buffer(
                    buffer,
                    SSH_ENCODE_UINT32(p1->xauth_authorization_group_ids[i]),
                    SSH_FORMAT_END);
        if (len != 4)
        {
            SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
            goto error;
        }
        total_len += len;
    }

    /* Encode remote access attributes to export buffer. */
    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32_STR(ras_attrs, ras_attrs_len),
                            SSH_FORMAT_END);
    if (len == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
        goto error;
    }
    total_len += len;

    /* Append the encoded IKE SA to export buffer. */
    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32_STR(encoded_ike_sa,
                                                  encoded_ike_sa_len),
                            SSH_FORMAT_END);
    if (len == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
        goto error;
    }
    total_len += len;

    ssh_free(local_id);
    ssh_free(remote_id);
    ssh_free(second_local_id);
    ssh_free(second_remote_id);
    ssh_free(eap_remote_id);
    ssh_free(second_eap_remote_id);
    ssh_free(ras_attrs);
    ssh_free(encoded_ike_sa);

    SSH_DEBUG(SSH_D_LOWOK, ("IKE SA %@ - %@ exported, len %d",
                            pm_ike_spi_render, p1->ike_sa->ike_spi_i,
                            pm_ike_spi_render, p1->ike_sa->ike_spi_r,
                            total_len));

    return total_len;

   error:
    SSH_DEBUG(SSH_D_FAIL, ("Could not export IKE SA %@ - %@",
                           pm_ike_spi_render, p1->ike_sa->ike_spi_i,
                           pm_ike_spi_render, p1->ike_sa->ike_spi_r));

    ssh_free(local_id);
    ssh_free(remote_id);
    ssh_free(second_local_id);
    ssh_free(second_remote_id);
    ssh_free(eap_remote_id);
    ssh_free(second_eap_remote_id);
    ssh_free(ras_attrs);
    ssh_free(encoded_ike_sa);

    /* Remove any already encoded data from buffer. */
    ssh_buffer_consume_end(buffer, total_len);

    return 0;
}

/***************************** IKE SA import *********************************/

/* Context data for IKE SA installation */
struct SshPmImportIkeInstallRec
{
#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
    /* Keep this element first, RAS state machine relies on it. */
    SshPmIkev2ConfQueryStruct query[1];
    SshIkev2ExchangeDataStruct ed;
    SshIkev2SaExchangeDataStruct ike_ed;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

    SshPmRemoteAccessAttrsStruct remote_access_attrs[1];
#endif /* SSHDIST_ISAKMP_CFG_MODE */

    SshBuffer buffer;
    SshPmSAImportStatus error;
    SshPm pm;
    SshPmP1 p1;
    SshIpAddrStruct remote_ip[1];
    SshIpAddrStruct server_ip[1];
    uint16_t server_local_port;

    unsigned char *encoded_ike_sa;
    size_t encoded_ike_sa_len;
    bool ike_sa_decoded;

    uint32_t import_flags;
    unsigned char *tunnel_app_id;
    size_t tunnel_app_id_len;

    SshFSMThreadStruct thread;

    SshPmIkeSAPreImportCB import_cb;
    void *import_context;
    SshPmIkeSAImportStatusCB status_cb;
    void *status_context;
};

typedef struct SshPmImportIkeInstallRec *SshPmImportIkeInstall;

/* FSM state declarations */
SSH_FSM_STEP(pm_st_ike_sa_import_start);
SSH_FSM_STEP(pm_st_ike_sa_import_install);
SSH_FSM_STEP(pm_st_ike_sa_import_failed);
SSH_FSM_STEP(pm_st_ike_sa_import_terminate);
#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
SSH_FSM_STEP(pm_st_ike_sa_import_ras_alloc);
SSH_FSM_STEP(pm_st_ike_sa_import_ras_done);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* Callback function for pre import hook */
static void
pm_ike_sa_import_hook_cb(SshPm pm, bool success, void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshPmImportIkeInstall install =
      (SshPmImportIkeInstall) ssh_fsm_get_tdata(thread);

    if (!success)
    {
        install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
        ssh_fsm_set_next(thread, pm_st_ike_sa_import_failed);
    }

    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Call import hook function */
SSH_FSM_STEP(pm_st_ike_sa_import_start)
{
    SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
    SshPmIkeSAEventHandleStruct ike_sa;

    SSH_FSM_SET_NEXT(pm_st_ike_sa_import_install);

    if (install->import_cb)
    {
        SSH_DEBUG(SSH_D_LOWOK, ("Calling IKE SA import hook"));

        ike_sa.event = SSH_PM_SA_EVENT_CREATED;
        ike_sa.p1 = install->p1;
        ike_sa.tunnel_application_identifier = install->tunnel_app_id;
        ike_sa.tunnel_application_identifier_len = install->tunnel_app_id_len;

        SSH_FSM_ASYNC_CALL({
          (*install->import_cb)(install->pm,
                                &ike_sa,
                                install->remote_ip,
                                pm_ike_sa_import_hook_cb,
                                thread,
                                install->import_context);
        });

        SSH_NOTREACHED;
    }

    return SSH_FSM_CONTINUE;
}

/* Install IKE SA */
SSH_FSM_STEP(pm_st_ike_sa_import_install)
{
    SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
    SshPm pm = install->pm;
    SshPmP1 p1 = install->p1;
    SshPmTunnel tunnel;

    SSH_DEBUG(SSH_D_LOWOK, ("IKE SA import install"));

    SSH_FSM_SET_NEXT(pm_st_ike_sa_import_terminate);

    tunnel = ssh_pm_p1_get_tunnel(pm, p1);
    if (tunnel == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA import failed, no tunnel found"));
        install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
        goto error;
    }

    p1->ike_sa->server = ssh_pm_servers_select_ike(pm, install->server_ip,
                                        SSH_PM_SERVERS_MATCH_PORT,
                                        SSH_INVALID_IFNUM,
                                        install->server_local_port,
                                        tunnel->routing_instance_id);

    if (p1->ike_sa->server == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("IKE SA import failed, no IKE server available"));
        install->error = SSH_PM_SA_IMPORT_ERROR_NO_SERVER_FOUND;
        goto error;
    }

    /* Now that p1->ike_sa->server is set, decode ikev2 library part
       of IKE SA */
    if (ssh_ikev2_decode_sa(
                p1->ike_sa,
                install->encoded_ike_sa, install->encoded_ike_sa_len)
        != SSH_IKEV2_ERROR_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA decode failed"));
        install->error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
        goto error;
    }
    install->ike_sa_decoded = true;

#ifdef SSHDIST_ISAKMP_CFG_MODE
    if (install->remote_access_attrs->num_addresses)
    {
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
        /* Reallocate RAS attributes if imported IKE SA has them
           and we are the server for this cfgmode IKE SA. */
        if ((install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_RAS) &&
            (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_REKEYED) == 0)
        {
            SSH_FSM_SET_NEXT(pm_st_ike_sa_import_ras_alloc);
            return SSH_FSM_CONTINUE;
        }
        else
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

        if (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_RAC)
        {
            /* For clients just copy the remote access attributes to the p1. */
            p1->remote_access_attrs =
              ssh_pm_dup_remote_access_attrs(install->remote_access_attrs);
            if (p1->remote_access_attrs == NULL)
            {
                SSH_DEBUG(SSH_D_FAIL, ("IKE SA RAS attribute copy failed"));
                install->error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
                goto error;
            }
        }
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */

    return SSH_FSM_CONTINUE;

   error:
    SSH_DEBUG(SSH_D_FAIL, ("IKE SA import install failed"));
    SSH_ASSERT(install->error != SSH_PM_SA_IMPORT_OK);
    SSH_FSM_SET_NEXT(pm_st_ike_sa_import_failed);
    return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
SSH_FSM_STEP(pm_st_ike_sa_import_ras_alloc)
{
    SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
    SshPm pm = install->pm;

    SSH_DEBUG(SSH_D_LOWOK, ("IKE SA import RAS allocation"));

    /* Fetch tunnel by `tunnel_id'. */
    install->query->tunnel =
        ssh_pm_tunnel_get_by_id(pm, install->p1->tunnel_id);
    if (install->query->tunnel == NULL)
    {
        install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
        goto error;
    }
    SSH_PM_TUNNEL_TAKE_REF(install->query->tunnel);
    install->query->client_attributes = install->remote_access_attrs;

    /* Initialize rest of RAS query context */
    install->query->p1 = install->p1;
    install->query->error = SSH_IKEV2_ERROR_OK;
    install->query->conf_payload = NULL;
    install->query->index = 0;
    install->query->ike_sa_import = true;
    install->query->fsm_st_done = pm_st_ike_sa_import_ras_done;

    /* Create a fake ike_ed and fill in identities from p1. */
    install->query->ed = &install->ed;
    install->query->ed->ike_sa = install->p1->ike_sa;
    install->query->ed->ref_cnt = 1;
    install->query->ed->ike_ed = &install->ike_ed;
    if (install->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
        install->query->ed->ike_ed->id_i = install->p1->local_id;
        install->query->ed->ike_ed->id_r = install->p1->remote_id;
    }
    else
    {
        install->query->ed->ike_ed->id_i = install->p1->remote_id;
        install->query->ed->ike_ed->id_r = install->p1->local_id;
    }

    /* Finally record that we have such SA. */
    ssh_adt_insert(install->pm->sad_handle->ike_sa_by_spi, install->p1);
    ssh_pm_ike_sa_hash_insert(install->pm, install->p1);

    SSH_FSM_SET_NEXT(pm_ras_attrs_alloc);
    return SSH_FSM_CONTINUE;

   error:
    SSH_DEBUG(SSH_D_FAIL, ("IKE SA import RAS allocation failed"));
    SSH_ASSERT(install->error != SSH_PM_SA_IMPORT_OK);
    SSH_FSM_SET_NEXT(pm_st_ike_sa_import_failed);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_st_ike_sa_import_ras_done)
{
    SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
    uint32_t i;

    /* Verify that the allocated RAS attributes match the requested.
       Delete IKE SA if they dont match. */
    if (install->p1->remote_access_attrs == NULL)
    {
        SSH_DEBUG(SSH_D_NICETOKNOW, ("RAS attribute allocation failed"));
        install->error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
        goto error;
    }
    else
    {
        for (i = 0; i < install->p1->remote_access_attrs->num_addresses; i++)
        {
            if (!SSH_IP_EQUAL(
                        &install->p1->remote_access_attrs->addresses[i],
                        &install->query->client_attributes->addresses[i]))
              break;
        }
        if (i != install->p1->remote_access_attrs->num_addresses ||
            i != install->query->client_attributes->num_addresses)
        {
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Allocated RAS attributes do not match requested "
                       "attributes"));
            install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
            goto error;
        }
    }

    if (install->query->tunnel)
      SSH_PM_TUNNEL_DESTROY(install->pm, install->query->tunnel);
    install->query->tunnel = NULL;

    SSH_FSM_SET_NEXT(pm_st_ike_sa_import_terminate);
    return SSH_FSM_CONTINUE;

   error:
    SSH_DEBUG(SSH_D_FAIL, ("IKE SA import RAS done failed"));
    SSH_ASSERT(install->error != SSH_PM_SA_IMPORT_OK);

    if (install->query->tunnel)
      SSH_PM_TUNNEL_DESTROY(install->pm, install->query->tunnel);
    install->query->tunnel = NULL;

    SSH_FSM_SET_NEXT(pm_st_ike_sa_import_failed);
    return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */


SSH_FSM_STEP(pm_st_ike_sa_import_failed)
{
    SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
    SshPmP1 p1 = install->p1;
    SshADTHandle handle;

    SSH_DEBUG(SSH_D_FAIL,
              ("Failed to import IKE SA %@ - %@, deleting SA",
               pm_ike_spi_render, p1->ike_sa->ike_spi_i,
               pm_ike_spi_render, p1->ike_sa->ike_spi_r));

    SSH_FSM_SET_NEXT(pm_st_ike_sa_import_terminate);

    SSH_ASSERT(install->error != SSH_PM_SA_IMPORT_OK);

    handle =
        ssh_adt_get_handle_to_equal(
                install->pm->sad_handle->ike_sa_by_spi,
                p1->ike_sa);
    if (handle != SSH_ADT_INVALID)
      ssh_adt_detach(install->pm->sad_handle->ike_sa_by_spi, handle);

    if (install->ike_sa_decoded)
      ssh_ikev2_ike_sa_uninit(p1->ike_sa);
    ssh_pm_p1_free(install->pm, p1);

    return SSH_FSM_CONTINUE;
}


/* Terminate state machine and call completion callback */
SSH_FSM_STEP(pm_st_ike_sa_import_terminate)
{
    SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
    SshPmIkeSAEventHandleStruct ike_sa;

    SSH_DEBUG(SSH_D_LOWOK, ("IKE SA import terminate state"));

    if (install->error != SSH_PM_SA_IMPORT_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to import IKE SA"));

        if (install->status_cb != NULL_FNPTR)
          (*install->status_cb)(install->pm,
                                install->error, NULL,
                                install->status_context);
    }
    else
    {
        SSH_DEBUG(SSH_D_MIDOK,
                  ("IKE SA %@ - %@ imported",
                   pm_ike_spi_render, install->p1->ike_sa->ike_spi_i,
                   pm_ike_spi_render, install->p1->ike_sa->ike_spi_r));

        /* Mark IKE SA completed. */
        install->p1->done = 1;

        /* Mark IKE SA unusable if it was a rekeyed IKE SA. */
        if (install->p1->rekeyed)
          install->p1->unusable = 1;

        /* Enable SA events for the IKE SA. */
        install->p1->enable_sa_events = 1;

        /* Finally record that we have such SA (if RAS it is already done). */
        if ((install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_RAS) == 0 ||
            (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_REKEYED) != 0)
        {
            ssh_adt_insert(
                    install->pm->sad_handle->ike_sa_by_spi,
                    install->p1);

            ssh_pm_ike_sa_hash_insert(install->pm, install->p1);
        }

#ifdef SSH_IPSEC_SMALL
        /* Register timeout for rekeying the IKE SA. */
        SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(
                install->p1,
                install->p1->expire_time -
                ssh_pm_ike_sa_soft_grace_time(install->p1) -
                monotonic_time_get());
#endif /* SSH_IPSEC_SMALL */

        if (install->status_cb != NULL_FNPTR)
        {
            /* Pass the IKE SA handle to application so that the possibly
               changed SA data can be re-exported. */
            memset(&ike_sa, 0, sizeof(ike_sa));
            ike_sa.p1 = install->p1;
            ike_sa.event = SSH_PM_SA_EVENT_CREATED;

            (*install->status_cb)(install->pm,
                                  SSH_PM_SA_IMPORT_OK, &ike_sa,
                                  install->status_context);
        }
    }

    return SSH_FSM_FINISH;
}

/* Thread destructor */
static void
pm_ike_sa_import_destructor(SshFSM fsm, void *context)
{
    SshPmImportIkeInstall install = (SshPmImportIkeInstall) context;

    if (install->remote_access_attrs->server_duid != NULL)
        ssh_free(install->remote_access_attrs->server_duid);

    ssh_free(install->tunnel_app_id);
    ssh_free(install);
}

/* Import IKE SA */

SshOperationHandle
ssh_pm_ike_sa_import(SshPm pm, SshBuffer buffer,
                     SshPmIkeSAPreImportCB import_callback,
                     void *import_callback_context,
                     SshPmIkeSAImportStatusCB status_callback,
                     void *status_callback_context)
{
    SshPmImportIkeInstall install = NULL;
    SshPmP1 p1 = NULL;
    uint32_t version, type;
    uint16_t local_auth_method, remote_auth_method;
    uint16_t second_local_auth_method, second_remote_auth_method;
    unsigned char *local_id, *remote_id;
    size_t local_id_len, remote_id_len;
    unsigned char *second_local_id, *second_remote_id;
    size_t second_local_id_len, second_remote_id_len;
    unsigned char *eap_remote_id;
    size_t eap_remote_id_len;
    unsigned char *second_eap_remote_id;
    size_t second_eap_remote_id_len;
    unsigned char *ras_attrs;
    size_t ras_attrs_len;
    unsigned char *old_ike_spi_i, *old_ike_spi_r;
    size_t old_ike_spi_i_len, old_ike_spi_r_len;
    size_t len = 0, i, offset;
    SshPmSAImportStatus error = SSH_PM_SA_IMPORT_OK;
    unsigned char *tunnel_app_id;
    size_t tunnel_app_id_len;
    int64_t expire_time;

    SSH_DEBUG(SSH_D_LOWOK, ("Entered IKE SA import"));

    if (buffer == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid input buffer"));
        error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
        goto error;
    }

    /* The SA import-export API is designed for local SA storage and recovery
       after crash or suspend. This means that SA import does not need to
       consider SA rekeys or updates because the SAs are always imported in to
       an freshly initialized system without conflicting SAs.

       Support for redundant fail-over GW type of scenario would
       require atleast the following changes:

       * Import of IKE SA rekeys: Instead of SA installation the new IKE SA
         needs to be installed using ssh_pm_ike_sa_rekey().

       * Import of IKE SA updates: IKEv2 library needs to be enhanced with a
         a public API for encoding/decoding of the window. The policy manager
         needs to be modified to update IKE SA addresses using
         ssh_pm_peer_p1_update_address().

       * Export of IKE SA updates/rekeys: Encoding/decoding of the UPDATED,
         REKEYED and DELETED SA events needs to be added.
    */

    /* Decode fixed IKE SA export header. */
    offset = ssh_decode_buffer(buffer,
                               SSH_DECODE_UINT32(&version),
                               SSH_DECODE_UINT32(&type),
                               SSH_FORMAT_END);
    if (offset == 0
        || version != SSH_PM_SA_EXPORT_VERSION
        || type != SSH_PM_SA_EXPORT_IKE_SA)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA export header"));
        error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
        goto error;
    }

    /* Allocate p1 object for imported IKE SA. */
    p1 = ssh_pm_p1_alloc(pm);
    if (p1 == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate p1"));
        error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    /* Allocate temporary context for import operation. */
    install = ssh_calloc(1, sizeof(*install));
    if (install == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Could not allocate import context for IKE SA"));
        error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    install->pm = pm;
    install->p1 = p1;
    install->error = SSH_PM_SA_IMPORT_OK;
    install->import_cb = import_callback;
    install->import_context = import_callback_context;
    install->status_cb = status_callback;
    install->status_context = status_callback_context;
    install->buffer = buffer;

    /* Decode p1 body. */
    offset =
        ssh_decode_buffer(
                install->buffer,
                SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                           install->remote_ip),
                SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                           install->server_ip),
                SSH_DECODE_UINT16(&install->server_local_port),
                SSH_DECODE_UINT64((uint64_t *) &expire_time),
                SSH_DECODE_UINT64(
                        (uint64_t *)&p1->lifetime),
                SSH_DECODE_UINT16(&p1->dh_group),
                SSH_DECODE_UINT16(&local_auth_method),
                SSH_DECODE_UINT16(&remote_auth_method),
                SSH_DECODE_UINT32_STR_NOCOPY(&local_id, &local_id_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&remote_id, &remote_id_len),
                SSH_DECODE_UINT16(&second_local_auth_method),
                SSH_DECODE_UINT16(&second_remote_auth_method),
                SSH_DECODE_UINT32_STR_NOCOPY(&second_local_id,
                                             &second_local_id_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&second_remote_id,
                                             &second_remote_id_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&eap_remote_id,
                                             &eap_remote_id_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&second_eap_remote_id,
                                             &second_eap_remote_id_len),
                SSH_DECODE_UINT32_STR(&p1->local_secret,
                                      &p1->local_secret_len),
                SSH_DECODE_UINT32(&p1->compat_flags),
                SSH_DECODE_UINT32(&p1->tunnel_id),
                SSH_DECODE_UINT32_STR_NOCOPY(&old_ike_spi_i,
                                             &old_ike_spi_i_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&old_ike_spi_r,
                                             &old_ike_spi_r_len),
                SSH_DECODE_UINT32(&install->import_flags),
                SSH_DECODE_UINT32_STR_NOCOPY(&tunnel_app_id,
                                             &tunnel_app_id_len),
                SSH_FORMAT_END);

    if (offset == 0)
      goto decode_error;

    p1->expire_time = monotonic_time_from_ssh_time(expire_time);

    if (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_REKEYED)
      p1->rekeyed = 1;
    else
      p1->rekeyed = 0;

    if (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_AUTH_GROUP_IDS_SET)
      p1->auth_group_ids_set = 1;
    else
      p1->auth_group_ids_set = 0;

    if (old_ike_spi_i_len != 8 || old_ike_spi_r_len != 8)
      goto decode_error;

    memcpy(p1->old_ike_spi_i, old_ike_spi_i, 8);
    memcpy(p1->old_ike_spi_r, old_ike_spi_r, 8);

    /* Decode identities. */
    p1->local_id = pm_util_decode_id(local_id, local_id_len);
    if (p1->local_id == NULL && local_id_len > 0)
      goto decode_error;
    p1->remote_id = pm_util_decode_id(remote_id, remote_id_len);
    if (p1->remote_id == NULL && remote_id_len > 0)
      goto decode_error;
    p1->local_auth_method = (SshPmAuthMethod) local_auth_method;
    p1->remote_auth_method = (SshPmAuthMethod) remote_auth_method;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
    p1->second_local_id = pm_util_decode_id(second_local_id,
                                            second_local_id_len);
    if (p1->second_local_id == NULL && second_local_id_len > 0)
      goto decode_error;
    p1->second_remote_id = pm_util_decode_id(second_remote_id,
                                             second_remote_id_len);
    if (p1->second_remote_id == NULL && second_remote_id_len > 0)
      goto decode_error;
    p1->second_local_auth_method = (SshPmAuthMethod) second_local_auth_method;
    p1->second_remote_auth_method =
        (SshPmAuthMethod) second_remote_auth_method;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#ifdef SSHDIST_IKE_EAP_AUTH
    p1->eap_remote_id = pm_util_decode_id(eap_remote_id, eap_remote_id_len);
    if (p1->eap_remote_id == NULL && eap_remote_id_len > 0)
      goto decode_error;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
    p1->second_eap_remote_id = pm_util_decode_id(second_eap_remote_id,
                                                 second_eap_remote_id_len);
    if (p1->second_eap_remote_id == NULL && second_eap_remote_id_len > 0)
      goto decode_error;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
    if (install->import_flags &
        SSH_PM_IKE_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK)
      p1->enable_blacklist_check = 1;
#endif /* SSH_PM_BLACKLIST_ENABLED */

    /* Decode authorization group ids. */
    len =
        ssh_decode_buffer(
                install->buffer,
                SSH_DECODE_UINT32(&p1->num_authorization_group_ids),
                SSH_FORMAT_END);
    if (len != 4)
      goto decode_error;
    if (p1->num_authorization_group_ids)
    {
        if (p1->auth_group_ids_set == 0)
          goto decode_error;

        p1->authorization_group_ids =
          ssh_calloc(p1->num_authorization_group_ids, sizeof(uint32_t));
        if (p1->authorization_group_ids == NULL)
        {
            error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
            goto error;
        }

        for (i = 0; i < p1->num_authorization_group_ids; i++)
        {
            len = ssh_decode_buffer(install->buffer,
                                    SSH_DECODE_UINT32(
                                    &p1->authorization_group_ids[i]),
                                    SSH_FORMAT_END);
            if (len != 4)
              goto decode_error;
        }
    }

    /* Decode XAUTH authorization group ids. */
    len = ssh_decode_buffer(install->buffer,
                            SSH_DECODE_UINT32(
                            &p1->num_xauth_authorization_group_ids),
                            SSH_FORMAT_END);
    if (len != 4)
      goto decode_error;
    if (p1->num_xauth_authorization_group_ids)
    {
        p1->xauth_authorization_group_ids =
          ssh_calloc(p1->num_xauth_authorization_group_ids, sizeof(uint32_t));
        if (p1->xauth_authorization_group_ids == NULL)
        {
            error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
            goto error;
        }

        for (i = 0; i < p1->num_xauth_authorization_group_ids; i++)
        {
            len = ssh_decode_buffer(install->buffer,
                                    SSH_DECODE_UINT32(
                                    &p1->xauth_authorization_group_ids[i]),
                                    SSH_FORMAT_END);
            if (len != 4)
              goto decode_error;
        }
    }

    /* Decode remote access attributes. */
    len = ssh_decode_buffer(install->buffer,
                            SSH_DECODE_UINT32_STR_NOCOPY(&ras_attrs,
                                                         &ras_attrs_len),
                            SSH_FORMAT_END);
    if (len == 0)
      goto decode_error;

#ifdef SSHDIST_ISAKMP_CFG_MODE
    if (ras_attrs_len > 0
        && pm_util_decode_p1_ras_attrs(ras_attrs, ras_attrs_len,
                                       install->remote_access_attrs) == false)
      goto decode_error;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

    /* Decode the ike library part of IKE SA. */
    len =
        ssh_decode_buffer(
                install->buffer,
                SSH_DECODE_UINT32_STR_NOCOPY(
                        &install->encoded_ike_sa,
                        &install->encoded_ike_sa_len),
                SSH_FORMAT_END);
    if (len == 0)
      goto decode_error;

    if (tunnel_app_id_len > 0)
    {
        install->tunnel_app_id = ssh_malloc(tunnel_app_id_len);
        if (install->tunnel_app_id == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Failed allocation memory for IKE SA's tunnel "
                       "application identifier"));
            goto decode_error;
        }
        memcpy(install->tunnel_app_id, tunnel_app_id, tunnel_app_id_len);
        install->tunnel_app_id_len = tunnel_app_id_len;
    }

    /* Check if there is unparsed data left in the buffer. */
    if (ssh_buffer_len(install->buffer))
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("IKE SA import buffer has %d bytes trailing garbage",
                   ssh_buffer_len(install->buffer)));
        goto decode_error;
    }

    /* Check IKE SA expiration. */
    if (p1->expire_time < monotonic_time_get())
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA %p has already expired", p1));
        error = SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED;
        goto error;
    }

    SSH_ASSERT(error == SSH_PM_SA_IMPORT_OK);
    SSH_DEBUG(SSH_D_LOWOK, ("Starting FSM thread for IKE SA import"));

    ssh_fsm_thread_init(&pm->fsm, &install->thread,
                        pm_st_ike_sa_import_start,
                        NULL_FNPTR,
                        pm_ike_sa_import_destructor,
                        install);

    /* IKE SA import cannot be aborted. */
    return NULL;

    /* Error handling. */
   decode_error:
    SSH_DEBUG(SSH_D_FAIL, ("IKE SA decode failed"));
    error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;

   error:
    SSH_ASSERT(error != SSH_PM_SA_IMPORT_OK);
    if (status_callback)
      (*status_callback)(pm, error, NULL, status_callback_context);

    if (p1)
      ssh_pm_p1_free(pm, p1);
    if (install)
    {
        if (install->remote_access_attrs->server_duid != NULL)
          ssh_free(install->remote_access_attrs->server_duid);
        ssh_free(install->tunnel_app_id);
        ssh_free(install);
    }

    return NULL;
}

SshPmSAImportStatus
ssh_pm_ike_sa_decode_deleted_event(
        SshBuffer buffer,
        uint32_t *ike_version_ret,
        unsigned char *ike_spi_i_ret,
        unsigned char *ike_spi_r_ret)
{
    size_t offset;
    uint32_t version;
    uint32_t type;
    uint32_t ike_version;

    if (buffer == NULL ||
        ike_version_ret == NULL ||
        ike_spi_i_ret == NULL ||
        ike_spi_r_ret == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
        return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_UINT32(&version),
                SSH_DECODE_UINT32(&type),
                SSH_FORMAT_END);

    if (offset == 0 ||
        version != SSH_PM_SA_EXPORT_VERSION ||
        type != SSH_PM_SA_EXPORT_IKE_SA_DESTROYED)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA export header"));
        return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_UINT32(&ike_version),
                SSH_DECODE_DATA(ike_spi_i_ret, (size_t) 8),
                SSH_DECODE_DATA(ike_spi_r_ret, (size_t) 8),
                SSH_FORMAT_END);

    if (offset == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IKE SA destroyed event decode failed"));
        return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

    if (ike_version != 2
#ifdef SSHDIST_IKEV1
         && ike_version != 1
#endif /* SSHDIST_IKEV1 */
        )
    {
        SSH_DEBUG(SSH_D_FAIL, ("Corrupted IKE SA destroyed event"));
        return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

    *ike_version_ret = ike_version;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Decoded IKEv%d SA I%02x%02x%02x%02x %02x%02x%02x%02x "
             "R%02x%02x%02x%02x %02x%02x%02x%02x",
             ike_version,
             ike_spi_i_ret[0], ike_spi_i_ret[1], ike_spi_i_ret[2],
             ike_spi_i_ret[3], ike_spi_i_ret[4], ike_spi_i_ret[5],
             ike_spi_i_ret[6], ike_spi_i_ret[7],
             ike_spi_r_ret[0], ike_spi_r_ret[1], ike_spi_r_ret[2],
             ike_spi_r_ret[3], ike_spi_r_ret[4], ike_spi_r_ret[5],
             ike_spi_r_ret[6], ike_spi_r_ret[7]));

    return SSH_PM_SA_IMPORT_OK;
}

/***************************** IPsec SA export *******************************/

/* Flag values for IPsec SA import flags. */
#define SSH_PM_IPSEC_SA_IMPORT_FLAG_RULE_FORWARD           0x0001
#define SSH_PM_IPSEC_SA_IMPORT_FLAG_REKEYED                0x0002
#define SSH_PM_IPSEC_SA_IMPORT_FLAG_TRANSPORT_MODE         0x0004
#define SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS    0x0008
#define SSH_PM_IPSEC_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK 0x0010

/* Context data for IPsec SA import/export */
typedef struct SshPmImportIpsecInstallRec
{
    bool done;
    SshPmSAImportStatus error;
    SshPm pm;
    SshPmQm qm;
    SshFSMThreadStruct thread;
    SshPmIpsecSAPreImportCB import_cb;
    void *import_context;
    SshPmIpsecSAImportStatusCB status_cb;
    void *status_context;

    /* Fields filled in by pm_ipsec_sa_decode(). */
    uint32_t tunnel_id;
    uint32_t rule_id;
    uint32_t import_flags;
    uint32_t life_seconds;
    SshTime expire_time;
    unsigned char ike_spi_i[8];
    unsigned char ike_spi_r[8];
    SshIkev2PayloadID local_ike_id;
    SshIkev2PayloadID remote_ike_id;
    unsigned char *tunnel_app_id;
    size_t tunnel_app_id_len;
    unsigned char *rule_app_id;
    size_t rule_app_id_len;
    struct IPSelectorGroup *selector_group;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
    const void *radius_acct_context;
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

} SshPmImportIpsecInstallStruct, *SshPmImportIpsecInstall;


/* Encode IPsec SA to `buffer'. */
static size_t
pm_ipsec_sa_encode(SshPm pm,
                   SshPmQm qm,
                   SshIkev2PayloadID local_id,
                   SshIkev2PayloadID remote_id,
                   unsigned char *ike_spi_i,
                   unsigned char *ike_spi_r,
                   SshBuffer buffer,
                   SshTime expire_time,
                   uint32_t import_flags)
{
    size_t len, total_len;
    unsigned char *exported_local_ike_id = NULL;
    size_t exported_local_ike_id_len = 0;
    unsigned char *exported_remote_ike_id = NULL;
    size_t exported_remote_ike_id_len = 0;
    char *tunnel_app_id = NULL;
    size_t tunnel_app_id_len = 0;
    const struct IPsecSaEndpoints *endpoints;
    const struct IPsecSaParams *ipsec_sa_params;
    struct IPsecSaKeyMaterial *key_material = NULL;
    struct SshIpAddrRec remote_natt_addr;
    struct SshIpAddrRec local_natt_addr;
    struct SshIpAddrRec remote_ip_addr;
    struct SshIpAddrRec local_ip_addr;
    uint32_t bytecount = 0;
    uint32_t inbound_spi = 0;

    SSH_PM_ASSERT_QM(qm);
    SSH_ASSERT(buffer != NULL);
    SSH_ASSERT(ike_spi_i != NULL);
    SSH_ASSERT(ike_spi_r != NULL);

    inbound_spi = qm->ipsec_sa_params.inbound_spi;

    endpoints = ipsec_sa_get_endpoints(pm->ipsec_control, inbound_spi);
    if (endpoints == NULL)
        goto encode_error;

    ipsec_sa_params =
        ipsec_sa_get_params(pm->ipsec_control,
                            inbound_spi);
    if (ipsec_sa_params == NULL)
        goto encode_error;

    key_material = &qm->ipsec_sa_keymaterial;

    /* Export expiry time. */
    if (expire_time == 0)
    {
        if (ipsec_sa_params->life_seconds == 0)
            expire_time = ssh_time() + SSH_PM_DEFAULT_IPSEC_SA_LIFE_SECONDS;
        else
            expire_time = ssh_time() + ipsec_sa_params->life_seconds;
    }

    /* Encode fixed IPsec SA export header. */
    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_VERSION),
                            SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_IPSEC_SA),
                            SSH_FORMAT_END);
    if (len == 0)
      goto encode_error;
    total_len = len;

    /* Encode rest. */

    exported_local_ike_id = pm_util_encode_id(local_id,
                                              &exported_local_ike_id_len);
    if (exported_local_ike_id == NULL && local_id != NULL)
      goto encode_error;
    exported_remote_ike_id = pm_util_encode_id(remote_id,
                                               &exported_remote_ike_id_len);
    if (exported_remote_ike_id == NULL && remote_id != NULL)
      goto encode_error;

    if (qm->forward)
      import_flags |= SSH_PM_IPSEC_SA_IMPORT_FLAG_RULE_FORWARD;

    if (qm->rekey)
      import_flags |= SSH_PM_IPSEC_SA_IMPORT_FLAG_REKEYED;

    if (qm->transport_sent && qm->transport_recv)
      import_flags |= SSH_PM_IPSEC_SA_IMPORT_FLAG_TRANSPORT_MODE;

#ifdef SSH_PM_BLACKLIST_ENABLED
  {
      SshPmPeer peer;

      peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);
      if (peer != NULL && peer->enable_blacklist_check)
        import_flags |= SSH_PM_IPSEC_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK;
  }
#endif /* SSH_PM_BLACKLIST_ENABLED */

    tunnel_app_id = qm->tunnel->application_identifier;
    tunnel_app_id_len = qm->tunnel->application_identifier_len;

    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_UINT32_STR(ike_spi_i, 8),
                SSH_ENCODE_UINT32_STR(ike_spi_r, 8),
                SSH_ENCODE_UINT32_STR(exported_local_ike_id,
                                      exported_local_ike_id_len),
                SSH_ENCODE_UINT32_STR(exported_remote_ike_id,
                                      exported_remote_ike_id_len),
                SSH_ENCODE_UINT32_STR(tunnel_app_id, tunnel_app_id_len),
                SSH_ENCODE_UINT32(import_flags),
                SSH_FORMAT_END);

    if (len == 0)
      goto encode_error;
    total_len += len;

    /* Encode IPsec SA params */
    in_addr_convert_to_sshipaddr(
            &ipsec_sa_params->natt_local_original_address,
            &local_natt_addr);
    in_addr_convert_to_sshipaddr(
            &ipsec_sa_params->natt_remote_original_address,
            &remote_natt_addr);
    if (ipsec_sa_params->selector_group != NULL)
    {
        bytecount = ipsec_sa_params->selector_group->bytecount;
    }

    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_UINT32(ipsec_sa_params->tunnel_id),
                SSH_ENCODE_UINT32(ipsec_sa_params->rule_id),
                SSH_ENCODE_UINT32(ipsec_sa_params->inbound_spi),
                SSH_ENCODE_UINT32(ipsec_sa_params->outbound_spi),
                SSH_ENCODE_UINT32(ipsec_sa_params->rekeyed_inbound_spi),
                SSH_ENCODE_UINT32(ipsec_sa_params->peer_handle),
                SSH_ENCODE_UINT32(ipsec_sa_params->log_facility),
                SSH_ENCODE_UINT32(ipsec_sa_params->ipproto),
                SSH_ENCODE_UINT32(ipsec_sa_params->integrity_algorithm_id),
                SSH_ENCODE_UINT32(ipsec_sa_params->encryption_algorithm_id),
                SSH_ENCODE_UINT32(ipsec_sa_params->dh_algorithm_id),
                SSH_ENCODE_BOOLEAN(ipsec_sa_params->ikev1_sa),
                SSH_ENCODE_BOOLEAN(ipsec_sa_params->tunnel_mode),
                SSH_FORMAT_END);

    if (len == 0)
        goto encode_error;
    total_len += len;

    /* Addresses, the encoding never returns 0 */
    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                   &local_natt_addr),
                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                   &remote_natt_addr),
                SSH_FORMAT_END);
    total_len += len;

    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_BOOLEAN(ipsec_sa_params->esn),
                SSH_ENCODE_BOOLEAN(ipsec_sa_params->initiator),
                SSH_ENCODE_BOOLEAN(ipsec_sa_params->rekey),
                SSH_ENCODE_BOOLEAN(ipsec_sa_params->rekeyed),
                SSH_ENCODE_BOOLEAN(ipsec_sa_params->last),
                SSH_ENCODE_UINT32(ipsec_sa_params->dont_fragment_bit_policy),
                SSH_ENCODE_BOOLEAN(ipsec_sa_params->stateful_fragment_check),
                SSH_ENCODE_UINT32(ipsec_sa_params->life_seconds),
                SSH_ENCODE_UINT64(ipsec_sa_params->life_bytes),
                SSH_ENCODE_UINT64(ipsec_sa_params->life_bytes_rekey),
                SSH_ENCODE_UINT64((uint64_t)expire_time),
                SSH_ENCODE_UINT32(ipsec_sa_params->natt_keepalive_timeout),
                SSH_ENCODE_UINT32(
                        ipsec_sa_params->idle_timeout_threshold_seconds),
                SSH_ENCODE_UINT32(
                        ipsec_sa_params->idle_event_interval_seconds),
                SSH_ENCODE_UINT32(ipsec_sa_params->policy_priority),
                SSH_ENCODE_UINT32(bytecount),
                SSH_FORMAT_END);
    if (len == 0)
      goto encode_error;

    if (bytecount != 0)
    {
    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_DATA(
                        (unsigned char *)ipsec_sa_params->selector_group,
                        bytecount),
                SSH_FORMAT_END);

    if (len == 0)
        goto encode_error;
    }

    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_UINT32(ipsec_sa_params->event_id),
                SSH_ENCODE_UINT32(ipsec_sa_params->event_id_inbound),
                SSH_ENCODE_UINT32(ipsec_sa_params->event_id_outbound),
                SSH_ENCODE_UINT32(ipsec_sa_params->seq_high),
                SSH_ENCODE_UINT32(ipsec_sa_params->seq_low),
                SSH_FORMAT_END);
    if (len == 0)
      goto encode_error;
    total_len += len;

    /* Encode IPsec SA endpoints */
    in_addr_convert_to_sshipaddr(
            &endpoints->local_address,
            &local_ip_addr);
    in_addr_convert_to_sshipaddr(
            &endpoints->remote_address,
            &remote_ip_addr);
    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                   &local_ip_addr),
                SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                   &remote_ip_addr),
                SSH_FORMAT_END);
    total_len += len;

    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_UINT32(endpoints->local_port),
                SSH_ENCODE_UINT32(endpoints->remote_port),
                SSH_ENCODE_BOOLEAN(endpoints->natt),
                SSH_ENCODE_BOOLEAN(endpoints->natt_local_nat),
                SSH_ENCODE_BOOLEAN(endpoints->natt_remote_nat),
                SSH_ENCODE_BOOLEAN(endpoints->natt_keepalive),
                SSH_FORMAT_END);

    if (len == 0)
      goto encode_error;
    total_len += len;

    /* Encode IPsec SA key material */
    len =
        ssh_encode_buffer(
                buffer,
                SSH_ENCODE_UINT32(key_material->integrity_keymaterial_len),
                SSH_ENCODE_UINT32(key_material->encryption_keymaterial_len),
                SSH_ENCODE_DATA(
                        key_material->inbound_integrity_keymaterial,
                        IPSEC_KEY_MATERIAL_BYTES_MAX),
                SSH_ENCODE_DATA(
                        key_material->inbound_encryption_keymaterial,
                        IPSEC_KEY_MATERIAL_BYTES_MAX),
                SSH_ENCODE_DATA(
                        key_material->outbound_integrity_keymaterial,
                        IPSEC_KEY_MATERIAL_BYTES_MAX),
                SSH_ENCODE_DATA(
                        key_material->outbound_encryption_keymaterial,
                        IPSEC_KEY_MATERIAL_BYTES_MAX),
                SSH_FORMAT_END);
    if (len == 0)
      goto encode_error;
    total_len += len;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
    len = pm_radius_acct_encode_session(buffer, qm->p1);
    if (len == 0)
    {
        goto encode_error;
    }
    total_len += len;
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
    ssh_free(exported_remote_ike_id);
    ssh_free(exported_local_ike_id);

    SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA %@ exported, len %d",
                            pm_ipsec_spi_render, qm, total_len));

    return total_len;

   encode_error:
    SSH_DEBUG(SSH_D_FAIL, ("IPsec SA %@ encode failed",
                           pm_ipsec_spi_render, qm));
    ssh_free(exported_remote_ike_id);
    ssh_free(exported_local_ike_id);

    return 0;
}

static size_t
pm_ipsec_sa_encode_deleted_event(SshPm pm,
                                 SshPmIPsecSAEventHandle ipsec_sa,
                                 SshBuffer buffer)
{
    size_t total_len;

    /* Encode fixed IPsec SA export header, IP protocol and SPI values. */
    total_len =
      ssh_encode_buffer(buffer,
                        SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_VERSION),
                        SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_IPSEC_SA_DESTROYED),
                        SSH_ENCODE_CHAR(ipsec_sa->ipproto),
                        SSH_ENCODE_UINT32(ipsec_sa->inbound_spi),
                        SSH_ENCODE_UINT32(ipsec_sa->outbound_spi),
                        SSH_FORMAT_END);
    if (total_len == 0)
      goto encode_error;

    SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA %@-%08lx destroyed event encoded",
                            ssh_ipproto_render, (uint32_t) ipsec_sa->ipproto,
                            (unsigned long) ipsec_sa->inbound_spi));

    return total_len;

   encode_error:
    SSH_DEBUG(SSH_D_FAIL, ("IPsec SA %@-%08lx destroyed event encode failed",
                           ssh_ipproto_render, (uint32_t) ipsec_sa->ipproto,
                           (unsigned long) ipsec_sa->inbound_spi));
    return 0;
}

size_t
ssh_pm_ipsec_sa_export(SshPm pm,
                       SshPmIPsecSAEventHandle ipsec_sa,
                       SshBuffer buffer)
{
    /* Check input parameters. */
    if (ipsec_sa == NULL || buffer == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
        return 0;
    }

    /* Check IPsec SA event. */
    switch (ipsec_sa->event)
    {
      case SSH_PM_SA_EVENT_CREATED:
      case SSH_PM_SA_EVENT_REKEYED:




        if ((ipsec_sa->qm == NULL || ipsec_sa->qm->p1 == NULL)
            && ipsec_sa->import_context == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Invalid IPsec SA event handle"));
            return 0;
        }

        if (ipsec_sa->qm != NULL && ipsec_sa->qm->p1 != NULL)
        {
            return pm_ipsec_sa_encode(pm, ipsec_sa->qm,
                                      ipsec_sa->qm->p1->local_id,
                                      ipsec_sa->qm->p1->remote_id,
                                      ipsec_sa->qm->p1->ike_sa->ike_spi_i,
                                      ipsec_sa->qm->p1->ike_sa->ike_spi_r,
                                      buffer,
                                      ipsec_sa->expire_time, 0);
        }
        else
        {
            SshPmImportIpsecInstall install = ipsec_sa->import_context;

            SSH_ASSERT(install != NULL);

            return pm_ipsec_sa_encode(pm, ipsec_sa->qm,
                                      install->local_ike_id,
                                      install->remote_ike_id,
                                      install->ike_spi_i,
                                      install->ike_spi_r,
                                      buffer,
                                      ipsec_sa->expire_time, 0);
        }

      case SSH_PM_SA_EVENT_DELETED:
        return pm_ipsec_sa_encode_deleted_event(pm, ipsec_sa, buffer);

      case SSH_PM_SA_EVENT_UPDATED:
        SSH_DEBUG(SSH_D_FAIL, ("Can't export IPsec SA UPDATED event"));
        break;
    }

    return 0;
}

/***************************** IPsec SA import *******************************/

/* Uninitialize contents of install. Note that this does not free install,
   as it might be allocated from stack. */
void
pm_ipsec_sa_import_uninit_install(SshPmImportIpsecInstall install)
{
    if (install->local_ike_id)
      ssh_pm_ikev2_payload_id_free(install->local_ike_id);
    if (install->remote_ike_id)
      ssh_pm_ikev2_payload_id_free(install->remote_ike_id);
    ssh_free(install->tunnel_app_id);
    ssh_free(install->rule_app_id);
    ssh_free(install->selector_group);
}

/* Setup rule and tunnel references to 'qm'. */
SshPmSAImportStatus
pm_ipsec_sa_import_prepare_qm(SshPm pm, SshPmQm qm, uint32_t tunnel_id,
                              uint32_t rule_id)
{
    if (qm->tunnel == NULL)
    {
        qm->tunnel = ssh_pm_tunnel_get_by_id(pm, tunnel_id);
        if (qm->tunnel == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could not find tunnel (id %d) for imported IPsec SA",
                       (int) tunnel_id));
            return SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
        }
        SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);
    }

    if (qm->rule == NULL)
    {
        qm->rule = ssh_pm_rule_lookup(pm, rule_id);
        if (qm->rule == NULL)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could not find rule (id %d) for imported IPsec SA",
                       (int) rule_id));
            return SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
        }
        SSH_PM_RULE_LOCK(qm->rule);
    }

    return SSH_PM_SA_IMPORT_OK;
}

/* FSM state declarations */
SSH_FSM_STEP(pm_st_ipsec_sa_import_start);
SSH_FSM_STEP(pm_st_ipsec_sa_import_install);
SSH_FSM_STEP(pm_st_ipsec_sa_import_invalidate_old_spis);
SSH_FSM_STEP(pm_st_ipsec_sa_import_terminate);

void pm_ipsec_sa_import_destructor(SshFSM fsm, void *context)
{
    SshPmImportIpsecInstall install = context;

    if (install->qm != NULL)
      ssh_pm_qm_free(install->pm, install->qm);

    pm_ipsec_sa_import_uninit_install(install);
    ssh_free(install);
}

/* Callback function for pre import hook */
static void
pm_ipsec_sa_import_hook_cb(SshPm pm, bool success, void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshPmImportIpsecInstall install =
      (SshPmImportIpsecInstall) ssh_fsm_get_tdata(thread);

    if (!success)
    {
        install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
        ssh_fsm_set_next(thread, pm_st_ipsec_sa_import_terminate);
    }

    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}


/* Call import hook function */
SSH_FSM_STEP(pm_st_ipsec_sa_import_start)
{
    SshPmImportIpsecInstall install = (SshPmImportIpsecInstall) thread_context;
    SshPmIPsecSAEventHandleStruct ipsec_sa;

    if (install->import_flags
        & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS)
    {
        SSH_FSM_SET_NEXT(pm_st_ipsec_sa_import_invalidate_old_spis);
        return SSH_FSM_CONTINUE;
    }

    /* Call pre-import hook for updating imported IPsec SA data. */
    SSH_FSM_SET_NEXT(pm_st_ipsec_sa_import_install);
    if (install->import_cb != NULL_FNPTR && !install->qm->aborted)
    {
        memset(&ipsec_sa, 0, sizeof(ipsec_sa));
        ipsec_sa.event = SSH_PM_SA_EVENT_CREATED;
        ipsec_sa.qm = install->qm;
        ipsec_sa.life_seconds = install->life_seconds;
        ipsec_sa.tunnel_application_identifier = install->tunnel_app_id;
        ipsec_sa.tunnel_application_identifier_len =
            install->tunnel_app_id_len;
        ipsec_sa.rule_application_identifier = install->rule_app_id;
        ipsec_sa.rule_application_identifier_len = install->rule_app_id_len;
        ipsec_sa.import_context = install;

        SSH_FSM_ASYNC_CALL({
            (*install->import_cb)(install->pm,
                                  &ipsec_sa,
                                  pm_ipsec_sa_import_hook_cb,
                                  thread,
                                  install->import_context);
          });
        SSH_NOTREACHED;
    }

    return SSH_FSM_CONTINUE;
}

/* Install IPsec SA */
SSH_FSM_STEP(pm_st_ipsec_sa_import_install)
{
    SshPmImportIpsecInstall install = (SshPmImportIpsecInstall) thread_context;
    SshPm pm = install->pm;
    SshPmQm qm = install->qm;
    struct IPsecSaEndpoints *endpoints = &qm->ipsec_sa_endpoints;
    struct SshIpAddrRec remote_address;
    struct SshIpAddrRec local_address;
    bool ok;

    SSH_ASSERT((install->import_flags
                & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS) == 0);

    SSH_FSM_SET_NEXT(pm_st_ipsec_sa_import_terminate);

    if (install->qm->aborted)
    {
        /* If qm was aborted then fail with no IKE SA found. */
        install->error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
        return SSH_FSM_CONTINUE;
    }

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
    if (install->radius_acct_context != NULL)
    {
        SshPmActiveCfgModeClient client = NULL;

        if (install->qm->p1 != NULL)
        {
            client = install->qm->p1->cfgmode_client;
        }
        else
        {
            uint32_t peer_handle = install->qm->peer_handle;

            if (peer_handle != SSH_IPSEC_INVALID_INDEX)
            {
                client =
                    ssh_pm_cfgmode_client_store_lookup(
                            install->pm,
                            peer_handle);
            }
            else
            {
                SSH_DEBUG(
                        SSH_D_FAIL,
                        ("No peer handle for RADIUS Accounting session!"));

            }
        }

        if (client != NULL)
        {
            pm_radius_acct_install_session(
                    client,
                    install->radius_acct_context);
        }
        else
        {
            SSH_DEBUG(
                    SSH_D_FAIL,
                    ("No cfgmode client for RADIUS Accounting session!"));
        }
    }
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

    /* Set rule and tunnel references to qm if application has not set them
       via import/export API. */
    install->error = pm_ipsec_sa_import_prepare_qm(pm, qm,
                                                   install->tunnel_id,
                                                   install->rule_id);
    if (install->error != SSH_PM_SA_IMPORT_OK)
      return SSH_FSM_CONTINUE;

    /* Convert addresses */
    in_addr_convert_to_sshipaddr(
            &endpoints->local_address,
            &local_address);
    in_addr_convert_to_sshipaddr(
            &endpoints->remote_address,
            &remote_address);

    /* Lookup or create peer for parentless IKEv1 keyed IPsec SAs. */
    SSH_ASSERT(qm->peer_handle == SSH_IPSEC_INVALID_INDEX);
    if (qm->p1 == NULL)
    {
        SSH_ASSERT(qm->ipsec_sa_params.ikev1_sa == true);

        /* Lookup a peer object for IKEv1 keyed IPsec SAs that have no
           parent IKE SA anymore. */
        qm->peer_handle =
            ssh_pm_peer_handle_lookup(
                    pm,
                    &remote_address,
                    endpoints->remote_port,
                    &local_address,
                    endpoints->local_port,
                    install->remote_ike_id,
                    install->local_ike_id,
                    qm->tunnel->routing_instance_id,
                    true);
        if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
        {
            /* Take a reference to peer handle for protecting
               qm->peer_handle. */
            ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
        }
        else
        {
            uint32_t flags = SSH_PM_PEER_CREATE_FLAGS_USE_IKEV1;

#ifdef SSH_PM_BLACKLIST_ENABLED
            if (install->import_flags
                & SSH_PM_IPSEC_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK)
              flags |= SSH_PM_PEER_CREATE_FLAGS_ENABLE_BLACKLIST_CHECK;
#endif /* SSH_PM_BLACKLIST_ENABLED */







            /* No matching peer found, create new peer. The function returns
               with one reference taken to the peer object. use that reference
               to protect qm->peer_handle. */
            qm->peer_handle =
              ssh_pm_peer_create_internal(
                      pm,
                      qm->tunnel->tunnel_id,
                      &remote_address,
                      endpoints->remote_port,
                      &local_address,
                      endpoints->local_port,
                      install->local_ike_id,
                      install->remote_ike_id,
                      SSH_IPSEC_INVALID_INDEX,
                      qm->tunnel->routing_instance_id,
                      flags,
                      false);
        }

        if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could create peer object for parentless IPsec SA"));
            install->error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
            return SSH_FSM_CONTINUE;
        }
    }
    else if (qm->p1 != NULL) /* IKEv2 */
    {
        qm->peer_handle = ssh_pm_peer_handle_by_p1(pm, qm->p1);
        if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
        {
            /* Take a reference to peer handle for protecting
               qm->peer_handle. */
            ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
        }
        else
        {
            /* No peer found, create a peer object temporarily. Use the
               returned peer handle reference for protecting
               qm->peer_handle. */
            qm->peer_handle =
              ssh_pm_peer_create(
                      pm,
                      qm->p1->tunnel_id,
                      &remote_address,
                      qm->p1->ike_sa->remote_port,
                      &local_address,
                      SSH_PM_IKE_SA_LOCAL_PORT(qm->p1->ike_sa),
                      qm->p1,
                      qm->tunnel->routing_instance_id);
        }
    }

    /* Register the SPI's with the policy manager.
       We require them to be unique. */
    if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
        install->error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
    }
    else
    {
        qm->ipsec_sa_params.peer_handle = qm->peer_handle;
        ok =
            ipsec_sa_import(
                    pm->ipsec_control,
                    &qm->ipsec_sa_params,
                    &qm->ipsec_sa_endpoints,
                    &qm->ipsec_sa_keymaterial,
                    install->selector_group);

        if (ok == true)
        {
            SshPmPeer peer;
            peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);
            SSH_ASSERT(peer != NULL);
            /* Increment the child SA counter for IKE SA's. */
            peer->num_child_sas++;
            ssh_pm_peer_handle_take_ref(pm, qm->ipsec_sa_params.peer_handle);

            /* Replace autostart with this SA */
            ssh_pm_qm_update_auto_start_status(pm, qm);

        }
        else
        {
            install->error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
        }
    }

    if (install->error == SSH_PM_SA_IMPORT_OK)
    {
        install->done = true;
    }
    else
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to import IPsec SA %@",
                               pm_ipsec_spi_render, install->qm));

        /* qm is freed in the qm_sub_thread_destructor. */
        install->qm = NULL;
    }

    return SSH_FSM_CONTINUE;
}

/* Invalidate old SPI values */
SSH_FSM_STEP(pm_st_ipsec_sa_import_invalidate_old_spis)
{
    SshPmImportIpsecInstall install = (SshPmImportIpsecInstall) thread_context;
    SshPm pm = install->pm;
    SshPmQm qm = install->qm;
    struct IPsecSaEndpoints *endpoints = &qm->ipsec_sa_endpoints;
    uint32_t inbound_spi = 0, outbound_spi = 0;
    SshInetIPProtocolID ipproto = 0;
    struct SshIpAddrRec remote_address;
    struct SshIpAddrRec local_address;
    bool ok;

    SSH_ASSERT(install->import_flags
               & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS);

    SSH_FSM_SET_NEXT(pm_st_ipsec_sa_import_terminate);

    if (install->qm->aborted)
    {
        /* If qm was aborted then fail with no IKE SA found. */
        install->error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
        return SSH_FSM_CONTINUE;
    }

    /* Set rule and tunnel references to qm if application has not set them
       via import/export API. */
    install->error = pm_ipsec_sa_import_prepare_qm(pm, qm,
                                                   install->tunnel_id,
                                                   install->rule_id);
    if (install->error != SSH_PM_SA_IMPORT_OK)
      return SSH_FSM_CONTINUE;

    /* Convert addresses */
    in_addr_convert_to_sshipaddr(
            &endpoints->local_address,
            &local_address);
    in_addr_convert_to_sshipaddr(
            &endpoints->remote_address,
            &remote_address);

    /* Lookup peer_handle for the IKE SA. */
    SSH_ASSERT(qm->peer_handle == SSH_IPSEC_INVALID_INDEX);
    if (qm->p1 != NULL)
    {
        qm->peer_handle = ssh_pm_peer_handle_by_p1(pm, qm->p1);
        if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
        {
            /* Take a reference to peer handle for protecting
               qm->peer_handle. */
            ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
        }
        else
        {
            /* No peer found, create a peer object temporarily. Use the
               returned peer handle reference for protecting
               qm->peer_handle. */
            qm->peer_handle =
              ssh_pm_peer_create(
                      pm,
                      qm->p1->tunnel_id,
                      &remote_address,
                      qm->p1->ike_sa->remote_port,
                      &local_address,
                      SSH_PM_IKE_SA_LOCAL_PORT(qm->p1->ike_sa),
                      qm->p1,
                      qm->tunnel->routing_instance_id);
        }
    }

    /* Lookup or create peer for parentless IKEv1 keyed IPsec SAs. */
    else
    {
        SSH_ASSERT(qm->ipsec_sa_params.ikev1_sa == true);

        /* Lookup a peer object for IKEv1 keyed IPsec SAs that have no
           parent IKE SA anymore. */
        qm->peer_handle =
            ssh_pm_peer_handle_lookup(
                    pm,
                    &remote_address,
                    endpoints->remote_port,
                    &local_address,
                    endpoints->local_port,
                    install->remote_ike_id,
                    install->local_ike_id,
                    qm->tunnel->routing_instance_id,
                    true);

        if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
        {
            /* Take a reference to peer handle for protecting
               qm->peer_handle. */
            ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
        }
        else
        {
            uint32_t flags = SSH_PM_PEER_CREATE_FLAGS_USE_IKEV1;







            /* No matching peer found, create new peer. The function returns
               with one reference taken to the peer object. use that reference
               to protect qm->peer_handle. */
            qm->peer_handle =
                ssh_pm_peer_create_internal(
                        pm,
                        qm->tunnel->tunnel_id,
                        &remote_address,
                        endpoints->remote_port,
                        &local_address,
                        endpoints->local_port,
                        install->local_ike_id,
                        install->remote_ike_id,
                        SSH_IPSEC_INVALID_INDEX,
                        qm->tunnel->routing_instance_id,
                        flags,
                        false);
        }

        if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could not create peer object for parentless "
                       "IPsec SA"));
            install->error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
            return SSH_FSM_CONTINUE;
        }
    }

    /* Send delete notification for the inbound SPI value. */
    ok =
        pm_ipsec_sa_params_get_spis(
                &qm->ipsec_sa_params,
                &inbound_spi,
                &outbound_spi,
                &ipproto);
    if (ok == false)
    {
        SSH_NOTREACHED;
    }

    ssh_pm_send_ipsec_delete_notification(
            pm,
            qm->peer_handle,
            qm->tunnel,
            qm->rule,
            ipproto,
            inbound_spi);

    /* Generate a deleted event for the IPsec SA. */
    ssh_pm_ipsec_sa_event_deleted(pm, outbound_spi, inbound_spi, ipproto);

    install->done = true;
    install->error = SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED;

    return SSH_FSM_CONTINUE;
}

/* Terminate state machine and call completion callback */
SSH_FSM_STEP(pm_st_ipsec_sa_import_terminate)
{
    SshPmImportIpsecInstall install = (SshPmImportIpsecInstall) thread_context;
    struct IPsecSaParams *ipsec_sa_params = &install->qm->ipsec_sa_params;
    SshPmIPsecSAEventHandleStruct ipsec_sa;

    if (!install->done)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to import IPsec SA"));

        SSH_ASSERT(install->error != SSH_PM_SA_IMPORT_OK);

        if (install->status_cb != NULL_FNPTR)
          (*install->status_cb)(install->pm,
                                install->error, NULL,
                                install->status_context);
    }
    else
    {
        SSH_DEBUG(SSH_D_MIDOK, ("IPsec SA %@ imported",
                                pm_ipsec_spi_render, install->qm));

        if (install->status_cb != NULL_FNPTR)
        {
            /* Pass the IPsec SA handle to application so that the possibly
               changed SA data can be re-exported. */
            memset(&ipsec_sa, 0, sizeof(ipsec_sa));
            ipsec_sa.import_context = install;

            if (install->import_flags
                & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS)
            {
                ipsec_sa.event = SSH_PM_SA_EVENT_DELETED;
                if (ipsec_sa_params->ipproto == SSH_IPPROTO_ESP ||
                    ipsec_sa_params->ipproto == SSH_IPPROTO_AH)
                {
                    ipsec_sa.inbound_spi = ipsec_sa_params->inbound_spi;
                    ipsec_sa.outbound_spi = ipsec_sa_params->outbound_spi;
                    ipsec_sa.ipproto = ipsec_sa_params->ipproto;
                }
                else
                  SSH_NOTREACHED;

                SSH_ASSERT(
                        install->error == SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED);
                SSH_DEBUG(SSH_D_MIDOK, ("IPsec SA %@ expired",
                                        pm_ipsec_spi_render, install->qm));
            }
            else if (install->import_flags &
                     SSH_PM_IPSEC_SA_IMPORT_FLAG_REKEYED)
            {
                install->qm->rekey = 1;
                ipsec_sa.event = SSH_PM_SA_EVENT_REKEYED;
                ipsec_sa.qm = install->qm;
                ipsec_sa.expire_time = install->expire_time;

                /* Patch SA lifetime to the original negotiated value. */
                ipsec_sa.qm->ipsec_sa_params.life_seconds =
                    install->life_seconds;

                SSH_ASSERT(install->error == SSH_PM_SA_IMPORT_OK);
            }
            else
            {
                ipsec_sa.event = SSH_PM_SA_EVENT_CREATED;
                ipsec_sa.qm = install->qm;
                ipsec_sa.expire_time = install->expire_time;

                /* Patch SA lifetime to the original negotiated value. */
                ipsec_sa.qm->ipsec_sa_params.life_seconds =
                    install->life_seconds;

                SSH_ASSERT(install->error == SSH_PM_SA_IMPORT_OK);
            }

            (*install->status_cb)(install->pm,
                                  install->error, &ipsec_sa,
                                  install->status_context);

            install->qm->rekey = 0;
        }
    }

    return SSH_FSM_FINISH;
}

/* Decode exported IPsec SA from `buffer'. */
static SshPmSAImportStatus
pm_ipsec_sa_decode(SshPm pm,
                   SshBuffer buffer,
                   SshPmQm *qm_ret,
                   SshPmImportIpsecInstall install)
{
    size_t offset;
    uint32_t version, type;
    unsigned char *exported_ike_spi_i, *exported_ike_spi_r;
    size_t exported_ike_spi_i_len, exported_ike_spi_r_len;
    unsigned char *exported_local_id, *exported_remote_id;
    size_t exported_local_id_len, exported_remote_id_len;
    unsigned char *exported_tunnel_app_id;
    size_t exported_tunnel_app_id_len;
    SshPmQm qm = NULL;
    SshTime exported_expire_time;
    SshPmSAImportStatus error = SSH_PM_SA_IMPORT_OK;
    SshIkev2PayloadID local_id = NULL;
    SshIkev2PayloadID remote_id = NULL;
    uint32_t exported_import_flags;
    struct IPsecSaEndpoints *endpoints = NULL;
    struct IPsecSaParams *ipsec_sa_params = NULL;
    struct IPsecSaKeyMaterial *key_material = NULL;
    struct SshIpAddrRec remote_natt_addr;
    struct SshIpAddrRec local_natt_addr;
    struct SshIpAddrRec remote_ip_addr;
    struct SshIpAddrRec local_ip_addr;
    uint32_t bytecount = 0;
    uint32_t life_seconds;

    SSH_ASSERT(qm_ret != NULL);
    SSH_ASSERT(buffer != NULL);
    SSH_ASSERT(install != NULL);

    /* Allocate qm */
    qm = ssh_pm_qm_alloc(pm, false);
    if (qm == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate qm for IPsec SA import"));
        error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    endpoints = &qm->ipsec_sa_endpoints;
    ipsec_sa_params = &qm->ipsec_sa_params;
    key_material = &qm->ipsec_sa_keymaterial;

    /* Decode fixed IPsec SA export header. */
    offset = ssh_decode_buffer(buffer,
                               SSH_DECODE_UINT32(&version),
                               SSH_DECODE_UINT32(&type),
                               SSH_FORMAT_END);
    if (offset == 0
        || version != SSH_PM_SA_EXPORT_VERSION
        || type != SSH_PM_SA_EXPORT_IPSEC_SA)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IPsec SA export header"));
        error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
        goto error;
    }

    /* Decode IPsec SA body. */
    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_UINT32_STR_NOCOPY(&exported_ike_spi_i,
                                             &exported_ike_spi_i_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&exported_ike_spi_r,
                                             &exported_ike_spi_r_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&exported_local_id,
                                             &exported_local_id_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&exported_remote_id,
                                             &exported_remote_id_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&exported_tunnel_app_id,
                                             &exported_tunnel_app_id_len),
                SSH_DECODE_UINT32(&exported_import_flags),
                SSH_FORMAT_END);
    if (offset == 0)
      goto decode_error;

    /* Decode IPsec SA Params */
    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_UINT32(&ipsec_sa_params->tunnel_id),
                SSH_DECODE_UINT32(&ipsec_sa_params->rule_id),
                SSH_DECODE_UINT32(&ipsec_sa_params->inbound_spi),
                SSH_DECODE_UINT32(&ipsec_sa_params->outbound_spi),
                SSH_DECODE_UINT32(&ipsec_sa_params->rekeyed_inbound_spi),
                SSH_DECODE_UINT32(&ipsec_sa_params->peer_handle),
                SSH_DECODE_UINT32((uint32_t *)&ipsec_sa_params->log_facility),
                SSH_DECODE_UINT32(&ipsec_sa_params->ipproto),
                SSH_DECODE_UINT32(
                        (uint32_t *)&ipsec_sa_params->integrity_algorithm_id),
                SSH_DECODE_UINT32(
                        (uint32_t *)&ipsec_sa_params->encryption_algorithm_id),
                SSH_DECODE_UINT32(
                        (uint32_t *)&ipsec_sa_params->dh_algorithm_id),
                SSH_DECODE_BOOLEAN(&ipsec_sa_params->ikev1_sa),
                SSH_DECODE_BOOLEAN(&ipsec_sa_params->tunnel_mode),
                SSH_FORMAT_END);
    if (offset == 0)
      goto decode_error;

    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                           &local_natt_addr),
                SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                           &remote_natt_addr),
                SSH_FORMAT_END);
    if (offset == 0)
      goto decode_error;

    in_addr_convert_from_sshipaddr(
            &ipsec_sa_params->natt_local_original_address,
            &local_natt_addr);
    in_addr_convert_from_sshipaddr(
            &ipsec_sa_params->natt_remote_original_address,
            &remote_natt_addr);

    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_BOOLEAN(&ipsec_sa_params->esn),
                SSH_DECODE_BOOLEAN(&ipsec_sa_params->initiator),
                SSH_DECODE_BOOLEAN(&ipsec_sa_params->rekey),
                SSH_DECODE_BOOLEAN(&ipsec_sa_params->rekeyed),
                SSH_DECODE_BOOLEAN(&ipsec_sa_params->last),
                SSH_DECODE_UINT32(&ipsec_sa_params->dont_fragment_bit_policy),
                SSH_DECODE_BOOLEAN(
                        &ipsec_sa_params->stateful_fragment_check),
                SSH_DECODE_UINT32(&life_seconds),
                SSH_DECODE_UINT64(&ipsec_sa_params->life_bytes),
                SSH_DECODE_UINT64(&ipsec_sa_params->life_bytes_rekey),
                SSH_DECODE_UINT64(
                        (uint64_t *) &exported_expire_time),
                SSH_DECODE_UINT32(
                        (uint32_t *)&ipsec_sa_params->natt_keepalive_timeout),
                SSH_DECODE_UINT32(
                        (uint32_t *)
                        &ipsec_sa_params->idle_timeout_threshold_seconds),
                SSH_DECODE_UINT32(
                        (uint32_t *)
                        &ipsec_sa_params->idle_event_interval_seconds),
                SSH_DECODE_UINT32(&ipsec_sa_params->policy_priority),
                SSH_DECODE_UINT32(&bytecount),
                SSH_FORMAT_END);
    if (offset == 0)
        goto decode_error;


    if (bytecount != 0)
    {
        install->selector_group =
            ssh_malloc(bytecount);

        if (install->selector_group == NULL)
            goto decode_error;

        offset =
            ssh_decode_buffer(
                    buffer,
                    SSH_DECODE_DATA((unsigned char *)install->selector_group,
                                    bytecount),
                    SSH_FORMAT_END);

        if (offset == 0)
            goto decode_error;
    }

    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_UINT32(
                        (uint32_t *)&ipsec_sa_params->event_id),
                SSH_DECODE_UINT32(&ipsec_sa_params->event_id_inbound),
                SSH_DECODE_UINT32(&ipsec_sa_params->event_id_outbound),
                SSH_DECODE_UINT32(&ipsec_sa_params->seq_high),
                SSH_DECODE_UINT32(&ipsec_sa_params->seq_low),
                SSH_FORMAT_END);
    if (offset == 0)
        goto decode_error;


    /* Decode IPsec SA endpoints */
    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                           &local_ip_addr),
                SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                           &remote_ip_addr),
                SSH_FORMAT_END);
    if (offset == 0)
      goto decode_error;

    in_addr_convert_from_sshipaddr(
            &endpoints->local_address,
            &local_ip_addr);
    in_addr_convert_from_sshipaddr(
            &endpoints->remote_address,
            &remote_ip_addr);


    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_UINT32(
                        (uint32_t *)&endpoints->local_port),
                SSH_DECODE_UINT32(
                        (uint32_t *)&endpoints->remote_port),
                SSH_DECODE_BOOLEAN(&endpoints->natt),
                SSH_DECODE_BOOLEAN(&endpoints->natt_local_nat),
                SSH_DECODE_BOOLEAN(&endpoints->natt_remote_nat),
                SSH_DECODE_BOOLEAN(&endpoints->natt_keepalive),
                SSH_FORMAT_END);
    if (offset == 0)
      goto decode_error;

    /* Decode IPsec SA key material */
    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_UINT32(
                        (uint32_t *)&key_material->integrity_keymaterial_len),
                SSH_DECODE_UINT32(
                        (uint32_t *)&key_material->encryption_keymaterial_len),
                SSH_DECODE_DATA(
                        key_material->inbound_integrity_keymaterial,
                        IPSEC_KEY_MATERIAL_BYTES_MAX),
                SSH_DECODE_DATA(
                        key_material->inbound_encryption_keymaterial,
                        IPSEC_KEY_MATERIAL_BYTES_MAX),
                SSH_DECODE_DATA(
                        key_material->outbound_integrity_keymaterial,
                        IPSEC_KEY_MATERIAL_BYTES_MAX),
                SSH_DECODE_DATA(
                        key_material->outbound_encryption_keymaterial,
                        IPSEC_KEY_MATERIAL_BYTES_MAX),
                SSH_FORMAT_END);

    if (offset == 0)
      goto decode_error;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
    install->radius_acct_context = pm_radius_acct_decode_session(buffer);
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

    /* Check if there is unparsed data left in the buffer. */
    if (ssh_buffer_len(buffer))
    {
        SSH_DEBUG(SSH_D_FAIL,
                  ("IPsec SA import buffer has %d bytes trailing garbage",
                   ssh_buffer_len(buffer)));
        goto decode_error;
    }

    if (exported_ike_spi_i_len != 8 || exported_ike_spi_r_len != 8)
      goto decode_error;

    qm->import = 1;

    install->rule_id = ipsec_sa_params->rule_id;
    install->tunnel_id = ipsec_sa_params->tunnel_id;
    install->import_flags = exported_import_flags;

    /* Decode IKE identities. */
    local_id = pm_util_decode_id(exported_local_id, exported_local_id_len);
    if (exported_local_id_len > 0 && local_id == NULL)
      goto decode_error;

    remote_id = pm_util_decode_id(exported_remote_id, exported_remote_id_len);
    if (exported_remote_id_len > 0 && remote_id == NULL)
      goto decode_error;

    install->life_seconds = life_seconds;
    install->expire_time = exported_expire_time;

    if (exported_import_flags & SSH_PM_IPSEC_SA_IMPORT_FLAG_RULE_FORWARD)
      qm->forward = 1;

    if (exported_import_flags & SSH_PM_IPSEC_SA_IMPORT_FLAG_TRANSPORT_MODE)
    {
        qm->transport_sent = 1;
        qm->transport_recv = 1;
    }

    memcpy(install->ike_spi_i, exported_ike_spi_i, exported_ike_spi_i_len);
    memcpy(install->ike_spi_r, exported_ike_spi_r, exported_ike_spi_r_len);

   if (exported_tunnel_app_id_len > 0)
    {
        install->tunnel_app_id = ssh_malloc(exported_tunnel_app_id_len);
        if (install->tunnel_app_id == NULL)
        {
            error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
            goto error;
        }
        memcpy(install->tunnel_app_id, exported_tunnel_app_id,
               exported_tunnel_app_id_len);
    }
    install->tunnel_app_id_len = exported_tunnel_app_id_len;

    install->local_ike_id = local_id;
    install->remote_ike_id = remote_id;

    *qm_ret = qm;

    SSH_ASSERT(error == SSH_PM_SA_IMPORT_OK);
    return error;

   decode_error:
    SSH_DEBUG(SSH_D_FAIL, ("IPsec SA decode failed"));
    error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;

   error:
    SSH_ASSERT(error != SSH_PM_SA_IMPORT_OK);

    if (qm)
      ssh_pm_qm_free(pm, qm);
    if (local_id)
      ssh_pm_ikev2_payload_id_free(local_id);
    if (remote_id)
      ssh_pm_ikev2_payload_id_free(remote_id);
    ssh_free(install->selector_group);
    install->selector_group = NULL;

    return error;
}


SshOperationHandle
ssh_pm_ipsec_sa_import(SshPm pm,
                       SshBuffer buffer,
                       SshPmIpsecSAPreImportCB import_callback,
                       void *import_callback_context,
                       SshPmIpsecSAImportStatusCB status_callback,
                       void *status_callback_context)
{
    SshPmImportIpsecInstall install = NULL;
    SshPmQm qm = NULL;
    SshPmSAImportStatus error = SSH_PM_SA_IMPORT_OK;
    SshTime now;

    /* The SA import-export API is designed for local SA storage and recovery
       after crash or suspend. This means that SA import does not need to
       consider SA rekeys or updates because the SAs are always imported in to
       an freshly initialized system without conflicting SAs.

       Support for redundant fail-over GW type of scenario would
       require atleast the following changes:

       * Import of IPsec SA rekeys: Rekeyed IPsec SAs must be
         installed as "rekeys", i.e. with `qm->rekey' set to 1. Some
         other minor changes maybe necessary.

       * Import of IPsec SA updates: New code needs to added for updating the
         peer object and the transforms. See ssh_pm_ipsec_sa_update().

       * Export of IPsec SA events: Encoding/decoding of the UPDATED, REKEYED
         and DELETED SA events needs to be added.
    */

    /* Check input parameters. */
    if (buffer == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
        error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
        goto fail;
    }

    /* Allocate installation context. */
    install = ssh_calloc(1, sizeof(*install));
    if (install == NULL)
    {
        error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
        goto fail;
    }
    install->done = false;
    install->pm = pm;

    /* Decode exported IPsec SA. */
    error = pm_ipsec_sa_decode(pm, buffer, &qm, install);
    if (error != SSH_PM_SA_IMPORT_OK)
      goto fail;

    SSH_ASSERT(qm != NULL);

    /* Lookup p1 by IKE SPI. */
    qm->p1 = (SshPmP1) ssh_pm_ike_sa_get_by_spi(pm->sad_handle,
                                                install->ike_spi_i);
    if (qm->p1 == NULL)
      qm->p1 = (SshPmP1) ssh_pm_ike_sa_get_by_spi(pm->sad_handle,
                                                  install->ike_spi_r);

    /* Check p1 usability for child SA import. */
    if (qm->p1 != NULL)
    {
        if (qm->p1->failed || qm->p1->unusable ||
            qm->p1->rekey_pending || !qm->p1->done)
        {
            SSH_DEBUG(SSH_D_FAIL,
                      ("IKE SA %p unusable, cannot import IPsec SA %@",
                       qm->p1->ike_sa,
                       pm_ipsec_spi_render, qm));
            error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
            goto fail;
        }
    }
    else if (qm->ipsec_sa_params.ikev1_sa == false)
    {
        SSH_DEBUG(SSH_D_FAIL, ("No IKEv2 SA found, cannot import IPsec SA"));
        error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
        goto fail;
    }

    /* Calculate remaining transform lifetime from absolute expiry time. */
    if ((install->import_flags &
         SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS)
        == 0)
    {
        now = ssh_time();
        if (install->expire_time <= now)
        {
            SSH_DEBUG(SSH_D_FAIL, ("IPsec SA has already expired"));
            /* Add 60 seconds to allow graceful rekey. */
            install->life_seconds = 60;
            install->expire_time = now + install->life_seconds;
        }

        qm->ipsec_sa_params.life_seconds =
            (uint32_t)(install->expire_time - now);

        /* Handle possible host clock mismatch. */
        if (install->life_seconds > 0 &&
            qm->ipsec_sa_params.life_seconds > install->life_seconds)
        {
            SSH_DEBUG(
                    SSH_D_NICETOKNOW,
                    ("Negotiated IPsec SA lifetime is smaller than "
                     "expiry time "
                     "indicates, setting lifetime to %d seconds",
                     (unsigned long) install->life_seconds));
            qm->ipsec_sa_params.life_seconds = install->life_seconds;
        }
    }

    /* Start installation */
    install->qm = qm;
    install->import_cb = import_callback;
    install->import_context = import_callback_context;
    install->status_cb = status_callback;
    install->status_context = status_callback_context;

    ssh_fsm_thread_init(&pm->fsm, &install->thread,
                        pm_st_ipsec_sa_import_start,
                        NULL_FNPTR,
                        pm_ipsec_sa_import_destructor,
                        install);

    SSH_ASSERT(error == SSH_PM_SA_IMPORT_OK);
    return NULL;

   fail:
    SSH_DEBUG(SSH_D_FAIL, ("IPSec SA import failed"));
    SSH_ASSERT(error != SSH_PM_SA_IMPORT_OK);

    if (qm)
      ssh_pm_qm_free(pm, qm);

    if (install)
    {
        /* If there is no IKE SA for an IPsec SA that is waiting
           for old SPI invalidation, then return error SA expired. */
        if ((install->import_flags
             & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS)
            && error == SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND)
          error = SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED;

        pm_ipsec_sa_import_uninit_install(install);
        ssh_free(install);
    }

    if (status_callback != NULL_FNPTR)
      (*status_callback)(pm, error, NULL, status_callback_context);

    return NULL;
}

SshPmSAImportStatus
ssh_pm_ipsec_sa_decode_deleted_event(
        SshBuffer buffer,
        SshInetIPProtocolID *ipproto_ret,
        uint32_t *inbound_spi_ret,
        uint32_t *outbound_spi_ret)
{
    size_t offset;
    uint32_t version;
    uint32_t type;
    unsigned int ipproto;
    uint32_t inbound_spi;
    uint32_t outbound_spi;

    if (buffer == NULL ||
        ipproto_ret == NULL ||
        inbound_spi_ret == NULL ||
        outbound_spi_ret == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
        return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_UINT32(&version),
                SSH_DECODE_UINT32(&type),
                SSH_FORMAT_END);

    if (offset == 0 ||
        version != SSH_PM_SA_EXPORT_VERSION ||
        type != SSH_PM_SA_EXPORT_IPSEC_SA_DESTROYED)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid IPsec SA export header"));
        return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

    offset =
        ssh_decode_buffer(
                buffer,
                SSH_DECODE_CHAR(&ipproto),
                SSH_DECODE_UINT32(&inbound_spi),
                SSH_DECODE_UINT32(&outbound_spi),
                SSH_FORMAT_END);

    if (offset == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("IPsec SA destroyed event decode failed"));
        return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

    if ((ipproto != SSH_IPPROTO_ESP && ipproto != SSH_IPPROTO_AH) ||
        inbound_spi == 0)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Corrupted IPsec SA destroyed event"));
        return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

    *ipproto_ret = (SshInetIPProtocolID) ipproto;
    *inbound_spi_ret = inbound_spi;
    *outbound_spi_ret = outbound_spi;

    SSH_DEBUG(
            SSH_D_LOWOK,
            ("Decoded IPsec SA %@-%08lx destroyed event",
             ssh_ipproto_render, (uint32_t) ipproto,
             (unsigned long) *inbound_spi_ret));

    return SSH_PM_SA_IMPORT_OK;
}

/*********************** IPsec SA update *************************************/

/** Update IKE SA to exported IPsec SA. The application should call this
    whenever it receives a SSH_PM_SA_EVENT_REKEYED event for an IKEv2 SA.
    This updates the exported IPsec SA in `buffer' to use the new IKEv2 SA
    identified by `ike_sa' event handle. */
size_t
ssh_pm_ipsec_sa_export_update_ike_sa(SshPm pm,
                                     SshBuffer buffer,
                                     SshPmIkeSAEventHandle ike_sa)
{
    SshPmImportIpsecInstallStruct install;
    SshPmQm qm = NULL;

    /* Check input parameters. */
    if (buffer == NULL || ike_sa == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
        return 0;
    }

    if (ike_sa->event != SSH_PM_SA_EVENT_REKEYED)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid input IKE SA event handle"));
        return 0;
    }

    /* Import the IPsec SA to a 'qm' data structure. */
    memset(&install, 0, sizeof(install));
    if (pm_ipsec_sa_decode(pm, buffer, &qm, &install) != SSH_PM_SA_IMPORT_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to import IPsec SA"));
        return 0;
    }

    SSH_ASSERT(qm != NULL);
    SSH_PM_ASSERT_QM(qm);

    /* Check if the parent IKE SA of the Quick-Mode is the IKE SA
       which has just been rekeyed. If so, then update the IKE SA
       information of the Quick-Mode and then re-export it to 'buffer'.
       Otherwise leave the exported SA in 'buffer' unmodified. */
    if (memcmp(install.ike_spi_i, ike_sa->p1->old_ike_spi_i, 8) == 0 &&
        memcmp(install.ike_spi_r, ike_sa->p1->old_ike_spi_r, 8) == 0)
    {
        if (pm_ipsec_sa_import_prepare_qm(pm, qm, install.tunnel_id,
                                          install.rule_id)
            != SSH_PM_SA_IMPORT_OK)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Failed to prepare qm"));
            goto out;
        }

        SSH_DEBUG(SSH_D_LOWOK,
                  ("Updating IKE SPI for IPsec SA %@ from %@ - %@ to %@ - %@",
                   pm_ipsec_spi_render, qm,
                   pm_ike_spi_render, install.ike_spi_i,
                   pm_ike_spi_render, install.ike_spi_r,
                   pm_ike_spi_render, ike_sa->p1->ike_sa->ike_spi_i,
                   pm_ike_spi_render, ike_sa->p1->ike_sa->ike_spi_r));

        SSH_DEBUG(SSH_D_MIDOK,
                  ("Re-linearizing the IPsec SA %@ after parent IKE SA rekey",
                   pm_ipsec_spi_render, qm));
        ssh_buffer_clear(buffer);
        pm_ipsec_sa_encode(pm, qm,
                           ike_sa->p1->local_id,
                           ike_sa->p1->remote_id,
                           ike_sa->p1->ike_sa->ike_spi_i,
                           ike_sa->p1->ike_sa->ike_spi_r,
                           buffer, install.expire_time,
                           install.import_flags);
    }
    else
      SSH_DEBUG(SSH_D_LOWOK,
                ("Ignoring update of IPsec SA %@ that was not negotiated with "
                 "IKE SA %@ - %@",
                 pm_ipsec_spi_render, qm,
                 pm_ike_spi_render, ike_sa->p1->ike_sa->ike_spi_i,
                 pm_ike_spi_render, ike_sa->p1->ike_sa->ike_spi_r));

   out:
    ssh_pm_qm_free(pm, qm);
    pm_ipsec_sa_import_uninit_install(&install);
    return ssh_buffer_len(buffer);
}

/** Internal utility function for matching IPsec SAs and IPsec SA events. */
static bool
pm_ipsec_sa_update_match_event(
        SshPm pm,
        SshPmQm qm,
        SshPmIPsecSAEventHandle ipsec_sa)
{
    SshInetIPProtocolID event_ipproto;
    uint32_t event_outbound_spi;
    uint32_t event_inbound_spi;
    SshInetIPProtocolID sa_ipproto;
    uint32_t sa_outbound_spi;
    uint32_t sa_inbound_spi;
    bool ok;

    SSH_PM_ASSERT_QM(qm);
    SSH_ASSERT(ipsec_sa != NULL);

    /* Extract protocol and SPI values from event handle. */
    event_ipproto = ssh_pm_ipsec_sa_get_protocol(pm, ipsec_sa);
    event_outbound_spi = ssh_pm_ipsec_sa_get_outbound_spi(pm, ipsec_sa);
    event_inbound_spi = ssh_pm_ipsec_sa_get_inbound_spi(pm, ipsec_sa);

    /* Extract protocol and SPI values from SA. */
    ok =
        pm_ipsec_sa_params_get_spis(
                &qm->ipsec_sa_params,
                &sa_inbound_spi,
                &sa_outbound_spi,
                &sa_ipproto);
    if (ok == false)
    {
        return false;
    }

    /* Compare */
    if (event_ipproto != sa_ipproto ||
        event_outbound_spi != sa_outbound_spi ||
        event_inbound_spi != sa_inbound_spi)
    {
        return false;
    }

    return true;
}


/** Update exported IPsec SA. The application should call this whenever it
    receives a SSH_PM_SA_EVENT_UPDATED for an IPsec SA. This updates the
    IPsec SA in `buffer' according to the changes in `ipsec_sa' event handle.
*/
size_t
ssh_pm_ipsec_sa_export_update(SshPm pm,
                              SshBuffer buffer,
                              SshPmIPsecSAEventHandle ipsec_sa)
{
    SshPmQm qm = NULL;
    SshPmImportIpsecInstallStruct install;

    memset(&install, 0, sizeof(install));

    if (ipsec_sa == NULL || buffer == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
        goto fail;
    }

    if (ipsec_sa->event != SSH_PM_SA_EVENT_UPDATED)
    {
        SSH_DEBUG(SSH_D_LOWOK,
                  ("Ignoring IPsec SA event (not SSH_PM_SA_EVENT_UPDATED)"));
        return ssh_buffer_len(buffer);
    }

    /* Import the IPsec SA to a 'qm' data structure. */
    if (pm_ipsec_sa_decode(pm, buffer, &qm, &install) != SSH_PM_SA_IMPORT_OK)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to decode exported IPsec SA"));
        goto fail;
    }

    SSH_ASSERT(qm != NULL);
    SSH_PM_ASSERT_QM(qm);

    /* Check that the IPsec SA event matches the imported IPsec SA. */
    if (pm_ipsec_sa_update_match_event(pm, qm, ipsec_sa))
    {
        if (pm_ipsec_sa_import_prepare_qm(pm, qm, install.tunnel_id,
                                          install.rule_id)
            != SSH_PM_SA_IMPORT_OK)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Failed to prepare qm"));
            goto fail;
        }

        /* Update qm. */
#ifdef DEBUG_LIGHT
        if (ipsec_sa->update_type == SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED)
        {
            struct IPsecSaEndpoints *endpoints = &qm->ipsec_sa_endpoints;
            struct SshIpAddrRec remote_address;
            struct SshIpAddrRec local_address;

            in_addr_convert_from_sshipaddr(
                    &endpoints->local_address,
                    &local_address);
            in_addr_convert_from_sshipaddr(
                    &endpoints->remote_address,
                    &remote_address);

            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Updating IPsec SA %@ to use addresses local %@:%d "
                     "remote %@:%d",
                     pm_ipsec_spi_render, qm,
                     ssh_ipaddr_render, &local_address,
                     endpoints->local_port,
                     ssh_ipaddr_render, &remote_address,
                     endpoints->remote_port));
        }
        else
#endif /* DEBUG_LIGHT */
        if (ipsec_sa->update_type ==
            SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED)
        {
            install.import_flags
              |= SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS;

            SSH_DEBUG(
                    SSH_D_LOWOK,
                    ("Marking IPsec SA %@ as waiting for old SPI invalidation",
                     pm_ipsec_spi_render, qm));
        }

        SSH_DEBUG(SSH_D_MIDOK,
                  ("Re-linearizing the updated IPsec SA %@",
                   pm_ipsec_spi_render, qm));

        /* Clear export buffer. */
        ssh_buffer_clear(buffer);

        /* Re-export updated IPsec SA. */
        pm_ipsec_sa_encode(pm, qm,
                           install.local_ike_id,
                           install.remote_ike_id,
                           install.ike_spi_i,
                           install.ike_spi_r,
                           buffer,
                           install.expire_time,
                           install.import_flags);
    }
    else
      SSH_DEBUG(SSH_D_LOWOK, ("Ignoring update event for IPsec SA %@",
                              pm_ipsec_spi_render, qm));

    ssh_pm_qm_free(pm, qm);
    pm_ipsec_sa_import_uninit_install(&install);

    return ssh_buffer_len(buffer);

    /* Error handling. */
   fail:
    if (qm != NULL)
      ssh_pm_qm_free(pm, qm);

    pm_ipsec_sa_import_uninit_install(&install);

    return 0;
}

#endif /* SSHDIST_IPSEC_SA_EXPORT */
