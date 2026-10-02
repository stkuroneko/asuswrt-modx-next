/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   HTTP interface for IPSec statistics.
*/

#include "sshincludes.h"
#include "quicksecpm_xmlconf_i.h"
#ifdef SSHDIST_HTTP_SERVER
#include "sshhttp.h"
#endif /* SSHDIST_HTTP_SERVER */
#include "sshmatch.h"
#include "ipsec_params.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "quicksecpm_audit.h"
#include "sshglobals.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshIpsecPmXmlConfHttp"

#ifdef SSHDIST_HTTP_SERVER
#ifdef SSH_IPSEC_XML_CONFIGURATION

#define HCELL(data)     "<th>", data, "</th>"
#define LCELL(data)     "<td>", data, "</td>"
#define CCELL(data)     "<td align=\"center\">", data, "</td>"
#define RCELL(data)     "<td align=\"right\">", data, "</td>"

#define SSH_FRIC    "<td align=\"right\">%d</td>"
#define SSH_FCSC    "<td align=\"center\">%s</td>"
#define SSH_FCFC    "<td align=\"center\">%@</td>"

#if SIZEOF_INT == 4
#define SSH_FR32C   "<td align=\"right\">%u</td>"
#define SSH_FR32T   "<td align=\"right\">%u s</td>"
#elif SIZEOF_LONG == 4
#define SSH_FR32C   "<td align=\"right\">%lu</td>"
#define SSH_FR32T   "<td align=\"right\">%lu s</td>"
#else
#error "neither int nor long is 32-bit"
#endif

/* Macros for 64-bit printing. On some platforms/compilers a 32-bit
   type will be used and the high order bits are lost. */
#ifdef HAVE_LONG_LONG
#define SSH_FR64C   "<td align=\"right\">%llu</td>"
#define SSH_V64C(v) ((unsigned long long)(v))
#else
#define SSH_FR64C   "<td align=\"right\">%lu</td>"
#define SSH_V64C(v) ((unsigned long)(v))
#endif

#define SSH_IPM_LINK(url, caption)                                      \
"<a href=\"" url "\"", frames ? " target=\"content\"" : "", ">",        \
(caption), "</a>"

/* Context data for the HTTP interface. */
struct SshIpmHttpStatisticsRec
{
    /* IP address to listen to. */
    SshIpAddrStruct address;

    /* Parameters. */
    SshIpmHttpStatisticsParamsStruct params;

    /* HTTP server context. */
    SshHttpServerContext http_server;
};

/* Object filtering flags. */
#define SSH_IPM_HTTP_F_TRANSFORM        0x00000001
#define SSH_IPM_HTTP_F_FLOW             0x00000002
#define SSH_IPM_HTTP_F_RULE             0x00000004
#define SSH_IPM_HTTP_F_TUNNEL_ID        0x00000008

/* Thread handling HTTP statistics operations. */
struct SshIpmHttpStatsRec
{
    /* FSM thread. */
    SshFSMThreadStruct thread;

    /* Flags. */
    unsigned int error : 1;       /* An error occurred. */
    unsigned int not_found : 1;   /* Requested object not found. */

    /* Object filtering flags. */
    uint32_t filter_flags;

    /* URI handler arguments. */
    SshHttpServerContext ctx;
    SshHttpServerConnection conn;
    SshStream stream;

    /* Buffer where the HTML content is generated. */
    SshBuffer buffer;

    /* Temporary buffer for formatting HTML. */
    char buf[1024];

    /* Sequence number. */
    uint32_t seqnum;

    /* Indexes of the objects currently processed. */
    uint32_t transform_index;
    uint32_t flow_index;
    uint32_t rule_index;

    /* Tunnel ID for filtering. */
    uint32_t tunnel_id;

    /* Hash for computing certificate identifications. */
    SshHash hash;
    size_t hash_digest_len;

    /* Certificate to lookup for the info_cert_cb(). */
    char *cert_id;
};

typedef struct SshIpmHttpStatsRec SshIpmHttpStatsStruct;
typedef struct SshIpmHttpStatsRec *SshIpmHttpStats;

/*************************** Protocol State names ***************************/

static SshPm
ssh_get_ipm_pm(
        SshIpmContext ipm)
{
    return (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);
}

/*************************** Formatting functions ***************************/

/* Construct a standard page header. */
static bool
ssh_ipm_http_page_header(SshIpmHttpStats ctx,
                         SshIpmHttpStatisticsParams params, SshBuffer buffer,
                         const char *title, bool toc)
{
    const char *prefix;
    const char *local_addr, *delim;
    char refresh_buf[128];
    char *refresh = "";

    if (toc)
    {
        prefix = SSH_IPSEC_VERSION_STRING_SHORT;
        delim = "";
    }
    else
    {
        if (params->frames)
        {
            delim = "";
            prefix = NULL;
        }
        else
        {
            prefix = SSH_IPSEC_VERSION_STRING_SHORT;
            delim = " - ";
        }
    }

    local_addr = ssh_http_server_get_local_address(ctx->conn);

    if (title == NULL)
      title = "";

    if (params->refresh)
    {
        ssh_snprintf(refresh_buf, sizeof(refresh_buf),
                     "<META http-equiv=\"Refresh\" content=\"%u\">\n",
                    (unsigned int) params->refresh);
        refresh = refresh_buf;
    }

    if (ssh_buffer_append_cstrs(buffer,
                                "\
  <!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\n\
     \"http://www.w3.org/TR/html4/strict.dtd\">\n\
  <html>\n\
  <head>\n\
  <META http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n",
                                refresh,
                                "<title>",
                                (prefix ? prefix : ""),
                                (prefix ? " - " : ""),
                                (prefix ? local_addr : ""),
                                delim,
                                title,
                                "</title>\n",
                                "</head>\n",
                                "<body>\n",
                                "<h1>",
                                (prefix ? prefix : ""),
                                (prefix ? " - ": ""),
                                (prefix ? local_addr : ""),
                                delim,
                                title,
                                "</h1>\n",
                                NULL) != SSH_BUFFER_OK)
      return false;

    return true;
}

/* Construct a standard page trailer. */
static bool
ssh_ipm_http_page_trailer(SshIpmHttpStatisticsParams params, SshBuffer buffer,
                          bool copyright)
{
    char *copy = "";

    if (copyright)
      copy = "\
  <hr>\n\
  <p>Copyright &copy; 2001-2016 \
  <a href=\"http://www.insidesecure.com\">INSIDE Secure Oy</a></p>\n";

    return ssh_buffer_append_cstrs(buffer,
                                   copy,
                                   "</body>\n",
                                   "</html>\n",
                                   NULL) == SSH_BUFFER_OK;
}


/************************** Static help functions ***************************/

/* Callback for global statistics querying from the version
   handler. */
static void
ssh_ipm_version_stats_cb(SshPm pm,
                         const SshPmGlobalStats pm_stats,
                         void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

    if (ssh_buffer_append_cstrs(
          ctx->buffer,
          "<table border>\n",
          "<tr><th>QuickSec Version</th>"
          "<td>" SSH_IPSEC_VERSION_STRING_SHORT "</td></tr>\n",
          "</table>\n",
          NULL) != SSH_BUFFER_OK)
      goto error;




































































    /* All done. */
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
    return;


    /* Error handling. */

   error:

    ctx->error = 1;
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static bool pm_ike_server_stats_cb(SshPm pm, SshIkev2Server server,
                                      void *context)
{
    SshIkev2GlobalStatistics stats = (SshIkev2GlobalStatistics) context;

    SSH_DEBUG(SSH_D_LOWOK, ("Adding statistics from server at %@",
                            ssh_ipaddr_render, server->ip_address));

    stats->total_ike_sas += server->statistics->total_ike_sas;
    stats->total_ike_sas_initiated +=
      server->statistics->total_ike_sas_initiated;
    stats->total_ike_sas_responded +=
      server->statistics->total_ike_sas_responded;

    stats->total_attempts += server->statistics->total_attempts;
    stats->total_attempts_initiated +=
      server->statistics->total_attempts_initiated;
    stats->total_attempts_responded +=
      server->statistics->total_attempts_responded;

    stats->total_packets_in += server->statistics->total_packets_in;
    stats->total_packets_out += server->statistics->total_packets_out;
    stats->total_octets_in += server->statistics->total_octets_in;
    stats->total_octets_out += server->statistics->total_octets_out;
    stats->total_retransmits += server->statistics->total_retransmits;
    stats->total_init_failures += server->statistics->total_init_failures;
    stats->total_init_no_response +=
        server->statistics->total_init_no_response;
    stats->total_resp_failures += server->statistics->total_resp_failures;
    return true;
}


static bool pm_ike_global_stats(SshPm pm, SshIkev2GlobalStatistics stats)
{
    return ssh_pm_foreach_ike_server(pm, pm_ike_server_stats_cb, stats);
}

/* Global statistics. */
static void
ssh_ipm_global_stats_cb(SshPm pm,
                        const SshPmGlobalStats pm_stats,
                        void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshIpmContext ipm = (SshIpmContext) ssh_fsm_get_gdata(thread);
    SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
    SshIkev2GlobalStatisticsStruct ike_stats;
    char daystr[64];
    SshTime uptime = ssh_time() - ipm->start_time;
    char *start_time = NULL;
    uint32_t hours, minutes;

    /* Format uptime. */

    if (uptime >= 60 * 60 * 24)
    {
        uint32_t days = (uint32_t)(uptime / (60 * 60 * 24));

        uptime -= days * 60 * 60 * 24;
        ssh_snprintf(daystr, sizeof(daystr), "%u day%s, ",
                     (unsigned int) days,
                     days > 1 ? "s" : "");
    }
    else
    {
        daystr[0] = '\0';
    }

    hours = (uint32_t)(uptime / (60 * 60));
    uptime -= hours * 60 * 60;

    minutes = (uint32_t)(uptime / 60);
    uptime -= minutes * 60;

    ssh_snprintf(ctx->buf, sizeof(ctx->buf), "%s%02u:%02u:%02u",
                 daystr,
                 (unsigned int) hours,
                 (unsigned int) minutes,
                 (unsigned int) uptime);

    /* Format start time. */
    start_time = ssh_readable_time_string(ipm->start_time, true);

    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "<table border>\n",

                                "<tr><th>Started at</th><td align=\"right\">",
                                start_time ? start_time : "???",
                                "</td></tr>\n",

                                "<tr><th>Uptime</th><td align=\"right\">",
                                ctx->buf,
                                "</td></tr>\n",

                                "</table>\n",
                                "<h2>Policy Manager</h2>\n",
                                NULL) != SSH_BUFFER_OK)
      goto error;

    /* Free the dynamically allocated start time string. */
    ssh_free(start_time);
    start_time = NULL;

    memset(&ike_stats, 0, sizeof(ike_stats));
    if (!pm_ike_global_stats(pm, &ike_stats))
      goto error;

    if (pm_stats)
    {
        ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                     "<tr>"
                     SSH_FR32C SSH_FR32C
                     SSH_FR32C SSH_FR32C
                     SSH_FR32C SSH_FR32C
                     SSH_FR32C SSH_FR32C
                     SSH_FR32C SSH_FR32C SSH_FR32C
                     "</tr>\n",
                     (unsigned int) pm_stats->num_p1_active,
                     (unsigned int) pm_stats->num_qm_active,
                     (unsigned int) pm_stats->num_p1_done,
                     (unsigned int) pm_stats->num_p1_failed,
                     (unsigned int) ike_stats.total_ike_sas_initiated,
                     (unsigned int) ike_stats.total_ike_sas_responded,
                     (unsigned int) pm_stats->num_qm_done,
                     (unsigned int) pm_stats->num_qm_failed,
                     (unsigned int) ike_stats.total_init_failures,
                     (unsigned int) ike_stats.total_init_no_response,
                     (unsigned int) ike_stats.total_resp_failures);


        if (ssh_buffer_append_cstrs(ctx->buffer,
                                    "<table border>\n",
                                    "<tr>",
                                    "<th colspan=\"2\">Active</th>",
                                    "<th colspan=\"6\">Total SAs</th>",
                                    "<th colspan=\"3\">IKE Errors</th>",
                                    "</tr>\n",
                                    "<tr>",
                                    "<th rowspan=\"2\">IKE SAs</th>",
                                    "<th colspan=\"1\">Negotiations</th>",

                                    "<th colspan=\"4\">Phase-1</th>",
                                    "<th colspan=\"2\">Quick-Mode</th>",

                                    "<th colspan=\"2\">Initiator</th>",
                                    "<th colspan=\"1\">Responder</th>",

                                    "</tr>\n",
                                    "<tr>",
                                    "<th>Quick-Mode</th>",

                                    "<th>Done</th><th>Failed</th>",
                                    "<th>Initiator</th><th>Responder</th>",
                                    "<th>Done</th><th>Failed</th>",

                                    "<th>Failures</th>",
                                    "<th>No response</th>",
                                    "<th>Failures</th>",

                                    "</tr>\n",
                                    ctx->buf,
                                    "</table>\n",
                                    NULL) != SSH_BUFFER_OK)
          goto error;
    }
    else
    {
        if (ssh_buffer_append_cstrs(ctx->buffer,
                                    "No statistics available.\n",
                                    NULL) != SSH_BUFFER_OK)
          goto error;
    }


    /* All done. */
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
    return;


    /* Error handling. */

   error:
    if (start_time != NULL)
        ssh_free(start_time);
    ctx->error = 1;
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS

#define IPM_HTTP_RADIUS_STAT(ctx, stats, field)                 \
  do {                                                          \
    ssh_snprintf(                                               \
            (ctx)->buf,                                         \
            sizeof((ctx)->buf),                                 \
            "<tr><th align=\"left\">" #field "</th><td> %u </td></tr>\n", \
            (unsigned) (stats)->field);                         \
    ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL);       \
  } while (0)

void
ssh_ipm_radius_acct_stats_cb(
        SshPm pm,
        const SshPmRadiusAcctStats stats,
        void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

    if (stats == NULL)
    {
        if (ssh_buffer_append_cstrs(
                    ctx->buffer,
                    "No RADIUS Accounting stats available.",
                    NULL)
            != SSH_BUFFER_OK)
          goto error;

        /* All done. */
        SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
        return;
    }

    ssh_snprintf(ctx->buf, sizeof(ctx->buf), "<table border>\n");


    if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL) != SSH_BUFFER_OK)
      goto error;

    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_on_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_off_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_start_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_stop_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_response_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_response_invalid_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_failed_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_too_long_ike_id_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_timeout_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_retransmit_count);
    IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_cancelled_count);

    ssh_snprintf(ctx->buf, sizeof(ctx->buf), "</table>\n");

    if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL) != SSH_BUFFER_OK)
      goto error;

    /* All done. */
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
    return;

   error:
      ctx->error = 1;
      SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

#undef IPM_HTTP_RADIUS_STAT

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT

/* Compute an unique ID (digest using the hash `hash') for the
   certificate `cert', `cert_len'. */
static bool
ssh_ipm_compute_cert_id(SshHash hash, size_t digest_len,
                        const unsigned char *cert, size_t cert_len,
                        char *idbuf, size_t idbuf_len)
{
    unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
    size_t i;

    ssh_hash_reset(hash);
    ssh_hash_update(hash, cert, cert_len);
    if (ssh_hash_final(hash, digest) != SSH_CRYPTO_OK)
      return false;

    if (idbuf_len < 2 * digest_len + 1)
      return false;

    for (i = 0; i < digest_len; i++)
      ssh_snprintf(idbuf + i * 2, 3, "%02X", digest[i]);

    return true;
}

/* Getting IKE certificates. */
static bool
ssh_ipm_ike_sa_info_cert_cb(SshPm pm,
                            SshPmIkeSaStats stats,
                            void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
    const unsigned char *ca;
    size_t ca_len;
    const unsigned char *cert;
    size_t cert_len;
    SshPmAuthData auth = NULL;
    char id_buf[2 * SSH_MAX_HASH_DIGEST_LENGTH + 1];

    auth = stats->auth;
    if (auth == NULL)
      goto error;

    ca = ssh_pm_auth_get_ca_certificate(auth, &ca_len);
    cert = ssh_pm_auth_get_certificate(auth, &cert_len);

    /* Try CA. */
    if (ca)
    {
        if (!ssh_ipm_compute_cert_id(ctx->hash, ctx->hash_digest_len,
                                     ca, ca_len, id_buf, sizeof(id_buf)))
          goto error;

        if (strcmp(id_buf, ctx->cert_id) == 0)
        {
            /* Found it. */
            if (ssh_buffer_append(ctx->buffer, ca, ca_len) != SSH_BUFFER_OK)
              goto error;

            /* Stop enumeration.  The error handler is find way to get
               out of here. */
            ctx->error = 1;
            goto error;
        }
    }

    /* Try cert. */
    if (cert)
    {
        if (!ssh_ipm_compute_cert_id(ctx->hash, ctx->hash_digest_len,
                                     cert, cert_len, id_buf, sizeof(id_buf)))
          goto error;

        if (strcmp(id_buf, ctx->cert_id) == 0)
        {
            /* Found it. */
            if (ssh_buffer_append(
                        ctx->buffer, cert, cert_len) != SSH_BUFFER_OK)
              goto error;

            /* Stop enumeration.  The error handler is find way to get
               out of here. */
            ctx->error = 1;
            goto error;
        }
    }

    return true;


    /* Error handling. */

   error:

    ctx->error = 1;
    return false;
}

/* A callback function for enumerating IKE servers while retrieving
   certificates from IKE SAs. */
static bool
ssh_ipm_ike_server_cert_cb(SshPm pm, SshIkev2Server server, void *context)
{
    SshFSMThread thread = (SshFSMThread) context;

    /* For each SA in the server. */
    return ssh_pm_ike_foreach_ike_sa(pm, server, ssh_ipm_ike_sa_info_cert_cb,
                                     thread);
}

#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */


/* Get IKE SA statistics. */
static bool
ssh_ipm_ike_sa_info_cb(SshPm pm,
                       SshPmIkeSaStats stats,
                       void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
    char ca_buf[256];
    char cert_buf[256];
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
    const unsigned char *ca;
    size_t ca_len;
    const unsigned char *cert;
    size_t cert_len;
    char id_buf[2 * SSH_MAX_HASH_DIGEST_LENGTH + 1];
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
    char *created_time = NULL;
    SshPmAuthData auth = NULL;
    SshTime created;
    SshIpAddrStruct local, remote;
    SshIkev2PayloadID local_id, remote_id;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
    SshIkev2PayloadID second_local_id, second_remote_id;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


    /* When the IKE SA was created */
    created = (SshTime)(stats->created);

    created_time = ssh_time_string(created);
    if (created_time == NULL)
      goto error;

    auth = stats->auth;
    if (auth == NULL)
      goto error;

    ssh_snprintf(ca_buf, sizeof(ca_buf), "");
    ssh_snprintf(cert_buf, sizeof(cert_buf), "");

    ssh_pm_auth_get_local_ip(auth, &local);
    ssh_pm_auth_get_remote_ip(auth, &remote);

    local_id = ssh_pm_auth_get_local_id(auth, 1);
    if (local_id == NULL)
      goto error;

    remote_id = ssh_pm_auth_get_remote_id(auth, 1);
    if (remote_id == NULL)
      goto error;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
    second_local_id = ssh_pm_auth_get_local_id(auth, 2);
    second_remote_id = ssh_pm_auth_get_remote_id(auth, 2);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
    /* Get trusted CA certificate. */
    ca = ssh_pm_auth_get_ca_certificate(auth, &ca_len);
    if (ca)
    {
        if (!ssh_ipm_compute_cert_id(ctx->hash, ctx->hash_digest_len,
                                     ca, ca_len, id_buf, sizeof(id_buf)))
          goto error;

        ssh_snprintf(ca_buf, sizeof(ca_buf),
                     "<a href=\"/ike/cert/%s\">CA</a>", id_buf);
    }

    /* Get peer certificate. */
    cert = ssh_pm_auth_get_certificate(auth, &cert_len);
    if (cert)
    {
        if (!ssh_ipm_compute_cert_id(ctx->hash, ctx->hash_digest_len,
                                     cert, cert_len, id_buf, sizeof(id_buf)))
          goto error;

        ssh_snprintf(cert_buf, sizeof(cert_buf),
                     "<a href=\"/ike/cert/%s\">Cert</a>", id_buf);
    }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

    ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                 "<tr>"
                 SSH_FR32C
                 SSH_FCSC
                 SSH_FRIC
                 SSH_FRIC
                 SSH_FCSC
                "<td align=\"center\">%@</td>"
                 "<td align=\"center\">%@</td>"
                "<td align=\"center\">%@</td>"
                 "<td align=\"center\">%@</td>"
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                "<td align=\"center\">%@</td>"
                 "<td align=\"center\">%@</td>"
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                 SSH_FCSC SSH_FCSC SSH_FCSC
                 SSH_FCSC SSH_FCSC
                "<td align=\"center\">%s (%d)</td>"
                 "</tr>\n",

                 (unsigned int) ++ctx->seqnum,
                 "yes",
                 (unsigned int) ssh_pm_auth_get_ike_version(auth),
                 (unsigned int) stats->num_child_sas,
                 created_time,
                 ssh_ipaddr_render, &local,
                 ssh_ipaddr_render, &remote,
                 ssh_pm_ike_id_render, local_id,
                 ssh_pm_ike_id_render, remote_id,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                 ssh_pm_ike_id_render, second_local_id,
                 ssh_pm_ike_id_render, second_remote_id,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                 stats->encrypt_algorithm,
                 stats->mac_algorithm,
                 stats->prf_algorithm,

                 ca_buf, cert_buf,
                 stats->routing_instance_name, stats->routing_instance_id);

    if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL) != SSH_BUFFER_OK)
      goto error;

    ssh_free(created_time);

    return true;

    /* Error handling. */

   error:

    ctx->error = 1;
    ssh_free(created_time);
    return false;
}

/* A callback function for enumerating IKE servers while retrieving
   IKE SA statistics. */
static bool
ssh_ipm_ike_server_cb(SshPm pm, SshIkev2Server server, void *context)
{
    SshFSMThread thread = (SshFSMThread) context;

    /* For each SA in the server. */
    return ssh_pm_ike_foreach_ike_sa(
            pm, server, ssh_ipm_ike_sa_info_cb, thread);
}



#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
/* A callback function for formatting address pool statistics. */
static bool
ssh_ipm_address_pool_stats_cb(SshPm pm, const SshPmAddressPoolStats stats,
                              void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
    char stats_type[30] = {'\0'};

    if ((stats->type & SSH_PM_REMOTE_ACCESS_DHCPV6_POOL) != 0)
      ssh_strcpy(stats_type, "DHCPv6 address pool");
    else if ((stats->type & SSH_PM_REMOTE_ACCESS_DHCP_POOL) != 0)
      ssh_strcpy(stats_type, "DHCP address pool");
    else
      ssh_strcpy(stats_type, "Generic address pool");

    if (ssh_buffer_append_cstrs(
                      ctx->buffer,
                      "<h2>Address Pool Statistics</h2>\n",
                      "<table border>\n",
                      "<tr>",
                      "<th>Address Pool Name</th>",
                      LCELL(stats->name),
                      "</tr><tr>",
                      "<th>Type</th>",
                      LCELL(stats_type),
                      "</tr><tr>",
                      "<th>Currently allocated addresses</th>",
                      "</tr>\n",
                      NULL) != SSH_BUFFER_OK)
      goto error;

    ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                 "<tr>"
                 SSH_FR32C
                 "</tr>\n",
                 (unsigned int) stats->current_num_allocated_addresses);

    if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,  NULL)
        != SSH_BUFFER_OK)
      goto error;

    if ((stats->type & SSH_PM_REMOTE_ACCESS_DHCP_POOL) != 0 ||
        (stats->type & SSH_PM_REMOTE_ACCESS_DHCPV6_POOL) != 0)
    {
          if (ssh_buffer_append_cstrs(
                      ctx->buffer,
                      "<tr>",
                      "<th colspan=\"3\">DHCP statistics</th>",
                      "<tr></tr>"
                      "<th>DHCP packets transmitted</th>",
                      "<th>DHCP packets received</th>",
                      "<th>DHCP packets dropped</th>",
                      "</tr>\n",
                      NULL) != SSH_BUFFER_OK)
            goto error;

          ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                       "<tr>"
                       SSH_FR32C SSH_FR32C SSH_FR32C
                       "</tr>\n",
                       (unsigned int) stats->dhcp.packets_transmitted,
                       (unsigned int) stats->dhcp.packets_received,
                       (unsigned int) stats->dhcp.packets_dropped);
          if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,  NULL)
              != SSH_BUFFER_OK)
            goto error;

          if (stats->type & SSH_PM_REMOTE_ACCESS_DHCPV6_POOL)
          {
              if (ssh_buffer_append_cstrs(
                          ctx->buffer,
                          "<tr>",
                          "<th colspan=\"2\">DHCP Relay messages:</th>",
                          "</tr><tr>",
                          "<th>RELAY-FORW sent</th>",
                          "<th>RELAY-REPL received</th>",
                          "</tr>\n",
                          NULL) != SSH_BUFFER_OK)
                goto error;

              ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                       "<tr>"
                       SSH_FR32C SSH_FR32C
                       "</tr>\n",
                       (unsigned int) stats->dhcp.dhcpv6_relay_forward,
                       (unsigned int) stats->dhcp.dhcpv6_relay_reply);
              if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,  NULL)
                  != SSH_BUFFER_OK)
                goto error;

              if (ssh_buffer_append_cstrs(
                          ctx->buffer,
                          "<tr>",
                          "<th colspan=\"7\">Per DHCP message:</th>",
                          "</tr><tr>",
                          "<th>SOLICIT sent</th>",
                          "<th>REPLY received</th>",
                          "<th>DECLINE sent</th>",
                          "<th>RENEW sent</th>",
                          "<th>RELEASE sent</th>",
                          "</tr>\n",
                          NULL) != SSH_BUFFER_OK)
                goto error;

              ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                       "<tr>"
                       SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C
                       SSH_FR32C
                           "</tr>\n",
                       (unsigned int) stats->dhcp.dhcpv6_solicit,
                       (unsigned int) stats->dhcp.dhcpv6_reply,
                       (unsigned int) stats->dhcp.dhcpv6_decline,
                       (unsigned int) stats->dhcp.dhcpv6_renew,
                       (unsigned int) stats->dhcp.dhcpv6_release);
              if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,  NULL)
                  != SSH_BUFFER_OK)
                goto error;
          }
          else
          {
              if (ssh_buffer_append_cstrs(
                          ctx->buffer,
                          "<tr>",
                          "<th colspan=\"7\">Per DHCP message:</th>",
                          "</tr><tr>",
                          "<th>DHCPDISCOVER sent</th>",
                          "<th>DHCPOFFER received</th>",
                          "<th>DHCPREQUEST sent</th>",
                          "<th>DHCPACK received</th>",
                          "<th>DHCPNAK received</th>",
                          "<th>DHCPDECLINE sent</th>",
                          "<th>DHCPRELEASE sent</th>",
                          "</tr>\n",
                          NULL) != SSH_BUFFER_OK)
                goto error;

              ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                       "<tr>"
                       SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C
                       SSH_FR32C SSH_FR32C SSH_FR32C
                       "</tr>\n",
                       (unsigned int) stats->dhcp.discover,
                       (unsigned int) stats->dhcp.offer,
                       (unsigned int) stats->dhcp.request,
                       (unsigned int) stats->dhcp.ack,
                       (unsigned int) stats->dhcp.nak,
                       (unsigned int) stats->dhcp.decline,
                       (unsigned int) stats->dhcp.release);

              if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,  NULL)
                  != SSH_BUFFER_OK)
                goto error;
          }
    }

    if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
        != SSH_BUFFER_OK)
      goto error;

    return true;

   error:
    return false;

}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/* Destructor for HTTP threads. */
static void
ssh_ipm_http_thread_destructor(SshFSM fsm, void *context)
{
    SshIpmContext ipm = ssh_fsm_get_gdata_fsm(fsm);
    SshIpmHttpStats ctx = (SshIpmHttpStats) context;

    ipm->http_statistics_refcount--;

    if (ctx->buffer)
      ssh_buffer_free(ctx->buffer);
    if (ctx->hash)
      ssh_hash_free(ctx->hash);
    ssh_free(ctx->cert_id);
    ssh_free(ctx);
}


/******************************* URI handlers *******************************/

/* Index page and Table of Contents. */

SSH_FSM_STEP(ssh_ipm_http_st_index);
SSH_FSM_STEP(ssh_ipm_http_st_toc);

/* Version information. */

SSH_FSM_STEP(ssh_ipm_http_st_version);
SSH_FSM_STEP(ssh_ipm_http_st_version_global_stats);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
/* Address pools. */
SSH_FSM_STEP(ssh_ipm_http_st_addrpools);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/* Interface information. */

SSH_FSM_STEP(ssh_ipm_http_st_interfaces);

/* Auditing */
SSH_FSM_STEP(ssh_ipm_http_st_audit);

/* Global statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_global);
SSH_FSM_STEP(ssh_ipm_http_st_global_stats);


#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS

/* RADIUS Accounting statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_radius_acct);
SSH_FSM_STEP(ssh_ipm_http_st_radius_acct_stats);

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/* IKE SA statistics. */
SSH_FSM_STEP(ssh_ipm_http_st_ike);
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
SSH_FSM_STEP(ssh_ipm_http_st_ike_cert);
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
SSH_FSM_STEP(ssh_ipm_http_st_ike_blacklist);
SSH_FSM_STEP(ssh_ipm_http_st_ike_blacklist_database);
#endif /* SSH_PM_BLACKLIST_ENABLED */

/* IPSec SA statistics. */
SSH_FSM_STEP(ssh_ipm_http_st_ipsec);

/* Trailer. */

SSH_FSM_STEP(ssh_ipm_http_st_trailer);

/* Request completed. */

SSH_FSM_STEP(ssh_ipm_http_st_done);

/* Error handling. */

SSH_FSM_STEP(ssh_ipm_http_st_error);
SSH_FSM_STEP(ssh_ipm_http_st_error_not_found);

SSH_FSM_STEP(ssh_ipm_http_st_finish);


/*************************** FSM state functions ****************************/

/* Index page and Table of Contents. */

SSH_FSM_STEP(ssh_ipm_http_st_index)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    if (!ipm->http_statistics->params.frames)
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_toc);
        return SSH_FSM_CONTINUE;
    }

    /* Frames are enabled. */

    if (ssh_buffer_append_cstrs(
          ctx->buffer,
          "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Frameset//EN\"\n"
          "  \"http://www.w3.org/TR/html4/frameset.dtd\">\n"
          "<html>\n"
          "<head>\n"
          "<title>" SSH_IPSEC_VERSION_STRING_SHORT "</title>\n"
          "</head>\n"
          "<frameset cols=\"20%,80%\">\n"
          "  <frame name=\"toc\" src=\"toc.html\">\n"
          "  <frame name=\"content\" src=\"version.html\">\n"
          "</frameset>\n"
          "</html>\n",
          NULL) != SSH_BUFFER_OK)
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    /* All done. */
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_done);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_http_st_toc)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
    bool frames = ipm->http_statistics->params.frames;

    if (!ssh_ipm_http_page_header(ctx,
                                  &ipm->http_statistics->params, ctx->buffer,
                                  NULL, true))
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

#ifdef SSH_IPSEC_STATISTICS
    if (ssh_buffer_append_cstrs(
          ctx->buffer,
          "<ul>\n",
          "  <li>", SSH_IPM_LINK("sas/ike/", "IKE SA Information"), "\n",
          "  <li>", SSH_IPM_LINK("sas/ipsec/", "IPsec SA counters"), "\n",
#ifdef SSH_PM_BLACKLIST_ENABLED
          "  <li>", SSH_IPM_LINK("ike-blacklist.html", "IKE Blacklist"), "\n",
#endif /* SSH_PM_BLACKLIST_ENABLED */
          "  <li>", SSH_IPM_LINK("audit/", "Audit Events"), "\n",
          "  <li>", SSH_IPM_LINK("global/", "Global Statistics"), "\n",
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
          "  <li>", SSH_IPM_LINK("addrpools/", "Address Pools"), "\n",
#ifdef SSHDIST_RADIUS
          "  <li>", SSH_IPM_LINK("radius_acct/",
                                 "Radius Accounting Statistics"), "\n",
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
          "  <li>", SSH_IPM_LINK("ifinfo.html", "Interface Information"), "\n",



          "</ul>\n",
          NULL) != SSH_BUFFER_OK)
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }
#else /* SSH_IPSEC_STATISTICS */

    if (ssh_buffer_append_cstrs(
          ctx->buffer,
          "<ul>\n",
          "  <li>Statistics Information are not available. To obtain "
          "statistics, recompile with SSH_IPSEC_STATISTICS defined.",
          "</ul>\n",
          NULL) != SSH_BUFFER_OK)
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }
#endif /* SSH_IPSEC_STATISTICS */

    /* Trailer. */
    if (!ssh_ipm_http_page_trailer(&ipm->http_statistics->params, ctx->buffer,
                                   frames ? false : true))
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    /* All done. */
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_done);
    return SSH_FSM_CONTINUE;
}

/* Version information. */

SSH_FSM_STEP(ssh_ipm_http_st_version)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
    SshPm pm = ssh_get_ipm_pm(ipm);


    if (!ssh_ipm_http_page_header(ctx,
                                  &ipm->http_statistics->params, ctx->buffer,
                                  "Memory Consumption", false))
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_version_global_stats);
    SSH_FSM_ASYNC_CALL(ssh_pm_get_global_stats(pm, ssh_ipm_version_stats_cb,
                                               thread));
    SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_version_global_stats)
{
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    if (ctx->error)
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
    else
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

    return SSH_FSM_CONTINUE;
}


/* Interface information. */

SSH_FSM_STEP(ssh_ipm_http_st_interfaces)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
    uint32_t ifnum;
    bool retval;
    SshPm pm = ssh_get_ipm_pm(ipm);

    if (!ssh_ipm_http_page_header(ctx,
                                  &ipm->http_statistics->params, ctx->buffer,
                                  "Interface Information", false))
      goto error;

    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "<table border>\n",
                                "<tr>"
                                "<th>Ifnum</th>"
                                "<th>Name</th>"
                                "<th>Address</th>"
                                "<th>Netmask</th>"
                                "<th>Broadcast</th>"
                                "<th>Routing Instance</th>"
                                "</tr>\n",
                                NULL) != SSH_BUFFER_OK)
      goto error;

    for (retval = ssh_pm_interface_enumerate_start(pm, &ifnum);
         retval;
         retval = ssh_pm_interface_enumerate_next(pm, ifnum, &ifnum))
    {
        uint32_t i, addrcount;
        char *ifname;
        const char *routing_instance_name;
        SshVriId routing_instance_id;

        if (!ssh_pm_interface_get_number_of_addresses(pm, ifnum,
                                                      &addrcount)
            || !ssh_pm_get_interface_name(pm, ifnum, &ifname))
          goto error;

        /* Format header for this interface. */

        if (ifname == NULL || ifname[0] == '\0')
          continue;

        ssh_snprintf(
                ctx->buf, sizeof(ctx->buf),
                "<tr><td rowspan=\"%u\">%u</td><td rowspan=\"%u\">%s</td>",
                (unsigned int) addrcount,
                (unsigned int) ifnum,
                (unsigned int) addrcount, ifname);

        if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL)
            != SSH_BUFFER_OK)
          goto error;

        /* Add addresses. */
        for (i = 0; i < addrcount; i++)
        {
            SshIpAddrStruct ip, netmask, broadcast;

            if (!ssh_pm_interface_get_address(pm, ifnum, i, &ip)
                || !ssh_pm_interface_get_netmask(pm, ifnum, i, &netmask))
              goto error;

            ssh_snprintf(
                    ctx->buf, sizeof(ctx->buf), "%s<td>%@</td><td>%@</td>",
                    i == 0 ? "" : "<tr>",
                    ssh_ipaddr_render, &ip,
                    ssh_ipmask_render, &netmask);

            if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL)
                != SSH_BUFFER_OK)
              goto error;

            if (SSH_IP_IS4(&ip))
            {
                if (!ssh_pm_interface_get_broadcast(pm, ifnum, i,
                                                    &broadcast))
                  goto error;

                ssh_snprintf(ctx->buf, sizeof(ctx->buf), "<td>%@</td>",
                             ssh_ipaddr_render, &broadcast);
            }
            else
            {
                ssh_snprintf(ctx->buf, sizeof(ctx->buf), "<td></td>");
            }

            if (i == 0)
            {
                if (!ssh_pm_interface_get_routing_instance_id(
                            pm, ifnum,
                            &routing_instance_id)
                    || !ssh_pm_get_interface_routing_instance_name(
                            pm, ifnum,
                            &routing_instance_name))
                  goto error;

                if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL)
                    != SSH_BUFFER_OK)
                  goto error;

                ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                             "<td rowspan=\"%u\">%s (%d)</td>",
                             (unsigned int) addrcount,
                             routing_instance_name,
                             routing_instance_id);
            }

            if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, "</tr>\n", NULL)
                != SSH_BUFFER_OK)
              goto error;
        }
    }
    if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
        != SSH_BUFFER_OK)
      goto error;

    /* All done. */
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
    return SSH_FSM_CONTINUE;


    /* Error handling. */

   error:

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
    return SSH_FSM_CONTINUE;
}

/* Audit events */
SSH_GLOBAL_DECLARE(SshPmAuditContext, pm_audit_context);
#define pm_audit_context SSH_GLOBAL_USE(pm_audit_context)

SSH_FSM_STEP(ssh_ipm_http_st_audit)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
    SshPmAuditEvent events;
    uint16_t nevents = 0;

    if (!ssh_ipm_http_page_header(ctx,
                                  &ipm->http_statistics->params, ctx->buffer,
                                  "Audit Events", false))
      goto error;

    /* Render audit event ring now */
    nevents = ssh_ipsecpm_audit_events(pm_audit_context, &events);
    if (nevents > 0)
    {
        if (ssh_buffer_append_cstrs(ctx->buffer, "<table border>\n", NULL)
            != SSH_BUFFER_OK)
          goto error;
        do {
          nevents -= 1;
          if (ssh_buffer_append_cstrs(ctx->buffer,
                                      "<tr>\n<td>\n",
                                      events[nevents].data,
                                      "</td>\n</tr>\n",
                                      NULL) != SSH_BUFFER_OK)
            goto error;
        } while (nevents != 0);

        if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
            != SSH_BUFFER_OK)
          goto error;

        ssh_free(events);
    }
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
    return SSH_FSM_CONTINUE;

   error:
    if (nevents)
      ssh_free(events);

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
    return SSH_FSM_CONTINUE;
}


/* Global statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_global)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
    SshPm pm = ssh_get_ipm_pm(ipm);

    if (!ssh_ipm_http_page_header(ctx,
                                  &ipm->http_statistics->params, ctx->buffer,
                                  "Global Statistics", false))
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_global_stats);
    SSH_FSM_ASYNC_CALL(ssh_pm_get_global_stats(pm, ssh_ipm_global_stats_cb,
                                               thread));
    SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_global_stats)
{
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    if (ctx->error)
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
    else
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

    return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS

/* RADIUS Accounting statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_radius_acct)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    if (!ssh_ipm_http_page_header(ctx,
                                  &ipm->http_statistics->params, ctx->buffer,
                                  "Radius Accounting Statistics", false))
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_radius_acct_stats);

    SSH_FSM_ASYNC_CALL(
            ssh_pm_radius_acct_get_stats(
                    ipm->pm,
                    ssh_ipm_radius_acct_stats_cb,
                    thread));

    SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_radius_acct_stats)
{
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    if (ctx->error)
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
    else
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

    return SSH_FSM_CONTINUE;
}

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
/* Address pool */
SSH_FSM_STEP(ssh_ipm_http_st_addrpools)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;


    if (!ssh_ipm_http_page_header(ctx,
                                  &ipm->http_statistics->params,
                                  ctx->buffer,
                                  "Address Pool Information",
                                  false))
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }


    if (ssh_pm_address_pool_foreach_get_stats(ipm->pm,
                                              ssh_ipm_address_pool_stats_cb,
                                              thread) == false)
      goto error;

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
    return SSH_FSM_CONTINUE;

   error:
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
    return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/* IKE SA statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_ike)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
    SshPm pm = ssh_get_ipm_pm(ipm);

    if (ssh_hash_allocate("md5", &ctx->hash) != SSH_CRYPTO_OK)
      goto error;

    ctx->hash_digest_len = ssh_hash_digest_length("md5");

    if (!ssh_ipm_http_page_header(ctx,
                                  &ipm->http_statistics->params, ctx->buffer,
                                  "IKE SA Information", false))
      goto error;

    if (ssh_buffer_append_cstrs(
                ctx->buffer,
                "<table border>\n",
                "<tr>",
                "<th rowspan=\"2\"></th>",
                "<th rowspan=\"2\">P1<br>Done</th>",
                "<th rowspan=\"2\">IKE version</th>",
                "<th rowspan=\"2\">Child SAs</th>",
                "<th rowspan=\"2\">Created</th>",
                "<th colspan=\"2\">IP Address</th>",
                "<th colspan=\"2\">Identity</th>",
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                "<th colspan=\"2\">Second Identity</th>",
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                "<th colspan=\"3\">Algorithm</th>",
                "<th colspan=\"2\">Certificate</th>",
                "<th rowspan=\"2\">Routing Instance</th>",
                "</tr>\n",

                "<tr>",
                HCELL("Local"), HCELL("Remote"),
                HCELL("Local"), HCELL("Remote"),
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                HCELL("Local"), HCELL("Remote"),
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                HCELL("Encryption"), HCELL("Hash"), HCELL("PRF"),
                HCELL("CA"), HCELL("Peer"),

                "</tr>\n",
                NULL) != SSH_BUFFER_OK)
      goto error;

    /* For each IKE server context in the policy manager. */
    if (!ssh_pm_foreach_ike_server(pm, ssh_ipm_ike_server_cb, thread))
      goto error;

    if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
        != SSH_BUFFER_OK)
      goto error;

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
    return SSH_FSM_CONTINUE;


    /* Error handling. */

   error:

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
    return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
SSH_FSM_STEP(ssh_ipm_http_st_ike_cert)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
    SshPm pm = ssh_get_ipm_pm(ipm);

    if (ssh_hash_allocate("md5", &ctx->hash) != SSH_CRYPTO_OK)
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    ctx->hash_digest_len = ssh_hash_digest_length("md5");

    /* For each IKE server context in the policy manager. */
    (void) ssh_pm_foreach_ike_server(pm, ssh_ipm_ike_server_cert_cb,
                                     thread);

    /* Did we find the certificate? */
    if (ssh_buffer_len(ctx->buffer) == 0)
    {
        /** No certificates found. */
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error_not_found);
        return SSH_FSM_CONTINUE;
    }

    /* Certificate found. */

    ssh_http_server_set_values(
          ctx->conn,
          SSH_HTTP_HDR_FIELD, "Content-Type", "application/x-x509-ca-cert",
          SSH_HTTP_HDR_END);

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_done);

    return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
static bool
ssh_ipm_blacklist_make_stats_row(SshIpmHttpStats ctx,
                                 char *name,
                                 uint32_t allowed_cnt,
                                 uint32_t blocked_cnt)
{
    ssh_snprintf(ctx->buf,
                 sizeof(ctx->buf),
                 SSH_FR32C SSH_FR32C,
                 (unsigned int) allowed_cnt,
                 (unsigned int) blocked_cnt);

    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "<tr>",
                                LCELL(name),
                                ctx->buf,
                                "</tr>",
                                NULL) != SSH_BUFFER_OK)
      return false;

    return true;
}

static bool
ssh_ipm_blacklist_stats_cb(SshPm pm,
                           const SshPmBlacklistStats stats,
                           void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
    uint32_t allowed_cnt;
    uint32_t blocked_cnt;

    if (stats == NULL)
    {
        ssh_buffer_append_cstrs(ctx->buffer,
                                "<h2>Statistics collection disabled</h2>\n",
                                NULL);
        goto out;
    }

    /* Show statistics */
    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "<h2>Statistics</h2>\n",
                                "<table border>\n",
                                NULL) != SSH_BUFFER_OK)
      goto out;

    /* Append counter of database entries */
    ssh_snprintf((char *)ctx->buf,
                 sizeof(ctx->buf),
                 "%u",
                 (unsigned int) stats->blacklist_entries);

    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "<tr>",
                                "<th>Number of database entries</th>",
                                "<td colspan=\"2\" align=\"right\">",
                                ctx->buf,
                                "</td>"
                                "</tr>\n",
                                NULL) != SSH_BUFFER_OK)
      goto out;

    /* Append statistics counters */
    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "<tr>",
                                HCELL("Counter"),
                                HCELL("Allowed"),
                                HCELL("Blocked"),
                                "</tr>\n",
                                NULL) != SSH_BUFFER_OK)
      goto out;

    allowed_cnt = stats->allowed_ikev2_r_initial_exchanges;
    blocked_cnt = stats->blocked_ikev2_r_initial_exchanges;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv2 [R] initial exchanges",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    allowed_cnt = stats->allowed_ikev2_r_create_child_exchanges;
    blocked_cnt = stats->blocked_ikev2_r_create_child_exchanges;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv2 [R] create child exchanges",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    allowed_cnt = stats->allowed_ikev2_r_ipsec_sa_rekeys;
    blocked_cnt = stats->blocked_ikev2_r_ipsec_sa_rekeys;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv2 [R] IPsec SA rekeys",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    allowed_cnt = stats->allowed_ikev2_r_ike_sa_rekeys;
    blocked_cnt = stats->blocked_ikev2_r_ike_sa_rekeys;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv2 [R] IKE SA rekeys",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    allowed_cnt = stats->allowed_ikev2_i_ipsec_sa_rekeys;
    blocked_cnt = stats->blocked_ikev2_i_ipsec_sa_rekeys;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv2 [I] IPsec SA rekeys",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    allowed_cnt = stats->allowed_ikev2_i_ike_sa_rekeys;
    blocked_cnt = stats->blocked_ikev2_i_ike_sa_rekeys;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv2 [I] IKE SA rekeys",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    allowed_cnt = stats->allowed_ikev1_r_main_mode_exchanges;
    blocked_cnt = stats->blocked_ikev1_r_main_mode_exchanges;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv1 [R] main mode exchanges",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    allowed_cnt = stats->allowed_ikev1_r_aggressive_mode_exchanges;
    blocked_cnt = stats->blocked_ikev1_r_aggressive_mode_exchanges;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv1 [R] aggressive mode exchanges",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    allowed_cnt = stats->allowed_ikev1_r_quick_mode_exchanges;
    blocked_cnt = stats->blocked_ikev1_r_quick_mode_exchanges;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv1 [R] quick mode exchanges",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    allowed_cnt = stats->allowed_ikev1_i_ipsec_sa_rekeys;
    blocked_cnt = stats->blocked_ikev1_i_ipsec_sa_rekeys;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv1 [I] IPsec SA rekeys",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    allowed_cnt = stats->allowed_ikev1_i_dpd_sa_creations;
    blocked_cnt = stats->blocked_ikev1_i_dpd_sa_creations;
    if (ssh_ipm_blacklist_make_stats_row(ctx,
                                         "IKEv1 [I] DPD SA creations",
                                         allowed_cnt,
                                         blocked_cnt) == false)
      goto out;

    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "</table>\n",
                                NULL) != SSH_BUFFER_OK)
      goto out;

   out:

    /* All done */
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_http_st_ike_blacklist)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    if (!ssh_ipm_http_page_header(ctx,
                                  &ipm->http_statistics->params,
                                  ctx->buffer,
                                  "Blacklist Information",
                                  false))
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_ike_blacklist_database);
    SSH_FSM_ASYNC_CALL(ssh_pm_blacklist_get_stats(ipm->pm,
                                                  ssh_ipm_blacklist_stats_cb,
                                                  thread));
    SSH_NOTREACHED;
}

static bool
ssh_ipm_blacklist_ike_id_info_cb(SshPm pm,
                                 SshPmBlacklistIkeIdInfo info,
                                 void *context)
{
    SshFSMThread thread = (SshFSMThread) context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

    /* Check if iteration has ended */
    if (info == NULL)
      return true;

#ifdef SSH_IPSEC_STATISTICS
    ssh_snprintf(ctx->buf,
                 sizeof(ctx->buf),
                 SSH_FR32C,
                 info->stat_blocked);
#endif /* SSH_IPSEC_STATISTICS */

    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "<tr>",
                                LCELL(info->type),
                                LCELL(info->data),
#ifdef SSH_IPSEC_STATISTICS
                                ctx->buf,
#endif /* SSH_IPSEC_STATISTICS */
                                "</tr>\n", NULL) != SSH_BUFFER_OK)
      return false;

    return true;
}

SSH_FSM_STEP(ssh_ipm_http_st_ike_blacklist_database)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "<h2>Database</h2>\n",
                                "<table border>\n",
                                "<tr>",
                                "<th>Type</th>",
                                "<th>Data</th>",
#ifdef SSH_IPSEC_STATISTICS
                                "<th>Blocked</th>",
#endif /* SSH_IPSEC_STATISTICS */
                                "</tr>\n",
                                NULL) != SSH_BUFFER_OK)
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    (void) ssh_pm_blacklist_foreach_ike_id(ipm->pm,
                                           ssh_ipm_blacklist_ike_id_info_cb,
                                           thread);

    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "</table>\n",
                                NULL) != SSH_BUFFER_OK)
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
    return SSH_FSM_CONTINUE;
}
#endif /* SSH_PM_BLACKLIST_ENABLED */

SSH_FSM_STEP(ssh_ipm_http_st_ipsec)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
    SshPm pm = ssh_get_ipm_pm(ipm);
    SshPmIPsecSaStatsStruct ipsec_sa_stats;

    memset(&ipsec_sa_stats, 0, sizeof(ipsec_sa_stats));

    if (!ssh_ipm_http_page_header(ctx,
                                  &ipm->http_statistics->params, ctx->buffer,
                                  "IPsec SA Counters", false))
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    if (ssh_buffer_append_cstrs(ctx->buffer,
                                "<table border>\n",
                                "<tr>",
                                "<th>Created</th>"
                                "<th>Rekeyed</th>"
                                "<th>Deleted</th>"
                                "</tr>\n",
                                NULL) != SSH_BUFFER_OK)
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    ssh_pm_get_ipsec_sa_stats(
            pm,
            &ipsec_sa_stats);

    ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                 "<tr>"
                 "<td>%d</td>"
                 "<td>%d</td>"
                 "<td>%d</td>"
                 "</tr>\n",
                 ipsec_sa_stats.created,
                 ipsec_sa_stats.rekeyed,
                 ipsec_sa_stats.deleted);

    if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL)
        != SSH_BUFFER_OK)
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
        != SSH_BUFFER_OK)
    {
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
        return SSH_FSM_CONTINUE;
    }

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_http_st_trailer)
{
    SshIpmContext ipm = (SshIpmContext) fsm_context;
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    if (!ssh_ipm_http_page_trailer(&ipm->http_statistics->params, ctx->buffer,
                                   true))
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
    else
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_done);

    return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_ipm_http_st_done)
{
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    /* Send buffer steals the buffer. */
    ssh_http_server_send_buffer(ctx->conn, ctx->buffer);
    ctx->buffer = NULL;

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_finish);

    return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_ipm_http_st_error)
{
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    ssh_http_server_error_code(
            ctx->conn, SSH_HTTP_STATUS_INTERNAL_SERVER_ERROR);

    if(ctx->stream)
      ssh_stream_destroy(ctx->stream);

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_finish);

    return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_ipm_http_st_error_not_found)
{
    SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

    ssh_http_server_error_not_found(ctx->conn);

    if(ctx->stream)
      ssh_stream_destroy(ctx->stream);

    SSH_FSM_SET_NEXT(ssh_ipm_http_st_finish);

    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_http_st_finish)
{
    return SSH_FSM_FINISH;
}


/* URI handler for all HTTP interface URIs. */
static  bool
ssh_ipm_http_handler(SshHttpServerContext http_ctx,
                     SshHttpServerConnection conn,
                     SshStream stream, void *context)
{
    SshIpmContext ipm = (SshIpmContext) context;
    SshIpmHttpStats ctx;
    const char *uri;
    char *cp;
    SshFSMStepCB first_state;

    ctx = ssh_calloc(1, sizeof(*ctx));
    if (ctx == NULL)
      goto error;

    ctx->buffer = ssh_buffer_allocate();
    if (ctx->buffer == NULL)
      goto error;

    ctx->ctx = http_ctx;
    ctx->conn = conn;
    ctx->stream = stream;

    /* Check what was requested. */
    uri = ssh_http_server_get_uri(conn);
    if (ssh_match_pattern(uri, "/index.html")
        || ssh_match_pattern(uri, "/"))
    {
        first_state = ssh_ipm_http_st_index;
    }
    else if (ssh_match_pattern(uri, "/toc.html"))
    {
        first_state = ssh_ipm_http_st_toc;
    }
    else if (ssh_match_pattern(uri, "/sas/ike/*"))
    {
        first_state = ssh_ipm_http_st_ike;
    }
    else if (ssh_match_pattern(uri, "/sas/ipsec/*"))
    {
        first_state = ssh_ipm_http_st_ipsec;
    }
    else if (ssh_match_pattern(uri, "/audit/*"))
    {
        first_state = ssh_ipm_http_st_audit;
    }
    else if (ssh_match_pattern(uri, "/global/*"))
    {
        first_state = ssh_ipm_http_st_global;
    }
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
    else if (ssh_match_pattern(uri, "/radius_acct/*"))
    {
        first_state = ssh_ipm_http_st_radius_acct;
    }
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
    else if (ssh_match_pattern(uri, "/addrpools/*"))
    {
        first_state = ssh_ipm_http_st_addrpools;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
    else if (ssh_match_pattern(uri, "/version.html"))
    {
        first_state = ssh_ipm_http_st_version;
    }
    else if (ssh_match_pattern(uri, "/ifinfo.html"))
    {
        first_state = ssh_ipm_http_st_interfaces;
    }
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
    else if (ssh_match_pattern(uri, "/ike/cert/*"))
    {
        cp = strrchr(uri, '/');

        ctx->cert_id = ssh_strdup(cp + 1);
        if (ctx->cert_id == NULL)
          goto error;

        first_state = ssh_ipm_http_st_ike_cert;
    }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
    else if (ssh_match_pattern(uri, "/ike-blacklist.html"))
    {
        first_state = ssh_ipm_http_st_ike_blacklist;
    }
#endif /* SSH_PM_BLACKLIST_ENABLED */
    else
    {
        first_state = ssh_ipm_http_st_error_not_found;
    }


    /* Start the thread from the start state */
    ipm->http_statistics_refcount++;
    ssh_fsm_thread_init(&ipm->fsm, &ctx->thread, first_state, NULL_FNPTR,
                        ssh_ipm_http_thread_destructor, ctx);

    /* All done. */
    return true;


    /* Error handling. */

   error:

    if (ctx)
    {
        if (ctx->buffer)
          ssh_buffer_free(ctx->buffer);
        ssh_free(ctx);
    }

    ssh_http_server_error_code(conn, SSH_HTTP_STATUS_INTERNAL_SERVER_ERROR);
    if (stream)
      ssh_stream_destroy(stream);

    return true;
}


/************************ Public interface functions ************************/

bool
ssh_ipm_http_statistics_start(SshIpmContext ctx,
                              SshIpmHttpStatisticsParams params)
{
    SshHttpServerParams http_params;
    char portbuf[16];
    SshIpAddrStruct addr;

    memset(&addr, 0, sizeof(addr));

    if (params->address)
    {



        if (!ssh_ipaddr_parse(&addr, params->address))
          return false;
    }
    else
    {
        SSH_IP_UNDEFINE(&addr);
    }

    if (ctx->http_statistics)
    {
        if (!SSH_IP_EQUAL(&ctx->http_statistics->address, &addr)
            || ctx->http_statistics->params.port != params->port
            || ctx->http_statistics->params.frames != params->frames
            || ctx->http_statistics->params.refresh != params->refresh)
          /* Stop the old server. */
          (void) ssh_ipm_http_statistics_stop(ctx);
        else
          /* The old server is running with correct parameters. */
          return true;
    }

    SSH_DEBUG(SSH_D_HIGHSTART, ("Starting HTTP interface on %s:%d",
                                params->address ? params->address : "<ANY>",
                                (int) params->port));

    ctx->http_statistics = ssh_calloc(1, sizeof(*ctx->http_statistics));
    if (ctx->http_statistics == NULL)
    {
        SSH_DEBUG(SSH_D_ERROR, ("Could not allocate context"));
        return false;
    }

    /* Store our address. */
    ctx->http_statistics->address = addr;

    /* One more reference to the HTTP statistics. */
    ctx->http_statistics_refcount++;

    /* Store parameters into the context. */
    ctx->http_statistics->params = *params;

    /* Start an HTTP server. */

    memset(&http_params, 0, sizeof(http_params));

    http_params.address = params->address;

    ssh_snprintf(portbuf, sizeof(portbuf), "%u", (unsigned int) params->port);
    http_params.port = portbuf;

    ctx->http_statistics->http_server = ssh_http_server_start(&http_params);
    if (ctx->http_statistics->http_server == NULL)
    {
        SSH_DEBUG(SSH_D_FAIL, ("Could not start HTTP server"));
        (void) ssh_ipm_http_statistics_stop(ctx);
        return false;
    }

    /* Set URI handler. */
    ssh_http_server_set_handler(ctx->http_statistics->http_server,
                                "*", 0,
                                ssh_ipm_http_handler, ctx);

    /* HTTP statistics started. */
    return true;
}


bool
ssh_ipm_http_statistics_stop(SshIpmContext ctx)
{
    if (ctx->http_statistics)
    {
        SSH_DEBUG(SSH_D_HIGHSTART, ("Stopping HTTP interface"));

        if (ctx->http_statistics->http_server)
          ssh_http_server_stop(ctx->http_statistics->http_server,
                               NULL_FNPTR, NULL);

        ssh_free(ctx->http_statistics);
        ctx->http_statistics = NULL;

        /* Remove our reference to the HTTP statistics. */
        ctx->http_statistics_refcount--;
    }

    if (ctx->http_statistics_refcount > 0)
      /* Still references left. */
      return false;

    /* HTTP statistics stopped. */
    return true;
}

#endif /* SSH_IPSEC_XML_CONFIGURATION */
#endif /* SSHDIST_HTTP_SERVER */
