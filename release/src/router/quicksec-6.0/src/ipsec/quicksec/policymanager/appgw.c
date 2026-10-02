/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Application gateway processing.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

#define SSH_DEBUG_MODULE "SshPmAppgw"


/************* Implementations of the application gateway APIs **************/

/* We have two implementations.  One using sort of `unified address
   space' concept where the firewall core and the application gateways
   are implemented in the same binary (policy manager).  The second
   API uses TCP to communicate between the firewall core and the
   gateway implementations. */

/* Register new application gateway to the system.  If the
   registration was successful, the function return SSH_APPGW_ERROR_OK
   and sets `registration_return' to point to the new registartion. */
SshAppgwError
ssh_appgw_api_register(SshPm pm,
                       SshAppgwParams params,
                       SshUInt32 flags,
                       SshIpAddr appgw_ip,
                       SshIpAddr appgw_ip6,
                       SshAppgwConnCB conn_callback, void *conn_context,
                       SshPmAppgw *appgw_return,
                       SshPmAppgwInstance *instance_return)
{
  SshPmAppgw appgw;
  SshPmAppgwInstance appgwi;
  SshUInt32 i;

  /* Do we already know this application gateway identification? */
  for (appgw = pm->appgws; appgw; appgw = appgw->next)
    if (strcmp(appgw->ident, params->ident) == 0
        && appgw->version == params->version
        && appgw->ipproto == params->ipproto)
      break;

  if (appgw == NULL)
    {
      /* Allocate a new appgw */
      appgw = ssh_pm_appgw_alloc(pm);
      if (appgw == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not allocate new application "
                                  "gateway for identification `%s'",
                                  params->ident));
          return SSH_APPGW_ERROR_TOOMANY;
        }

      /* Initialize this new registration. */

      SSH_ASSERT(strlen(params->ident) < sizeof(appgw->ident));
      strncpy(appgw->ident, params->ident, sizeof(appgw->ident));
      /* ensure NULL termination */
      appgw->ident[sizeof(appgw->ident) - 1] = 0;

      appgw->version = params->version;
      appgw->ipproto = params->ipproto;
      appgw->locals_destroyed = 0;

      appgw->conn_callback = conn_callback;
      appgw->conn_context = conn_context;
      memcpy(&appgw->appgw_conn_params, params, sizeof(*params));
      appgw->conn_flags = flags;

      appgw->next = pm->appgws;
      pm->appgws = appgw;
    }

  /* Does the application gateway have still space for one more host? */
  for (i = 0; i < SSH_PM_MAX_APPGW_HOSTS; i++)
    if (!appgw->hosts[i].valid)
      break;

  if (i >= SSH_PM_MAX_APPGW_HOSTS)
    {
      /* This application gateway is already fully served. */
      SSH_DEBUG(SSH_D_ERROR,
                ("Have already %d hosts serving application gateway `%s'",
                 (int) i, params->ident));
      return SSH_APPGW_ERROR_TOOMANY;
    }

  appgwi = &appgw->hosts[i];

  memset(appgwi, 0, sizeof(*appgwi));

  appgwi->valid = 1;
  if (appgw_ip)
    appgwi->gwip = *appgw_ip;
  if (appgw_ip6)
    appgwi->gwip6 = *appgw_ip6;
  appgwi->flags = flags;

  if (params->flow_idle_timeout)
    appgwi->flow_idle_timeout = params->flow_idle_timeout;
  else
    appgwi->flow_idle_timeout = SSH_APPGW_DEFAULT_TIMEOUT;

  appgwi->conn_callback = conn_callback;
  appgwi->conn_context = conn_context;

  *appgw_return = appgw;
  *instance_return = appgwi;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Registered APPGW API for appgw %s",
             params->ident));
  return SSH_APPGW_ERROR_OK;
}


/************* An unified address space application gateway API *************/

void
ssh_appgw_done(SshAppgwContext ctx)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) ctx->system_context;

  SSH_ASSERT(conn->state == SSH_PM_APPGW_CONNECTED);
  conn->state = SSH_PM_APPGW_DONE;

  if (ctx->session_end_event_generated == 0)
    ssh_appgw_audit_event(ctx, SSH_AUDIT_APPGW_SESSION_END,
                          SSH_AUDIT_ARGUMENT_END);

  ssh_fsm_continue(&conn->thread);
}

void
ssh_appgw_redirect(SshAppgwContext ctx,
                   const SshIpAddr new_responder_ip,
                   SshUInt16 new_responder_port)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) ctx->system_context;
  char ip_buf[32], int_buf[4];
  size_t ip_len;

  SSH_ASSERT(conn->state == SSH_PM_APPGW_REDIRECT);
  SSH_ASSERT(new_responder_ip != NULL);

  ctx->responder_ip = *new_responder_ip;
  ctx->responder_port = new_responder_port;

  SSH_DEBUG(SSH_D_LOWOK, ("Application gateway redirect: %@.%d -> %@.%d",
                          ssh_ipaddr_render, &ctx->responder_orig_ip,
                          (int) ctx->responder_orig_port,
                          ssh_ipaddr_render, &ctx->responder_ip,
                          (int) ctx->responder_port));

  if (!(SSH_IP_EQUAL(&ctx->responder_orig_ip, &ctx->responder_ip)
        && ctx->responder_orig_port == ctx->responder_port))
    {
      SSH_IP_ENCODE(&ctx->responder_ip, ip_buf, ip_len);
      SSH_PUT_16BIT(int_buf, ctx->responder_port);

      ssh_appgw_audit_event(ctx,
                            SSH_AUDIT_NOTICE,
                            SSH_AUDIT_TXT, "Redirecting connection",
                            SSH_AUDIT_TARGET_IP, ip_buf, ip_len,
                            SSH_AUDIT_TARGET_PORT, int_buf, 2,
                            SSH_AUDIT_ARGUMENT_END);
    }

  conn->state = SSH_PM_APPGW_START;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(&conn->thread);
}

/* Return audit parameter from either an audit_event array or
   a default value if it is not found. */
static SshAuditArgument
ssh_appgw_audit_param(SshAuditArgumentType type,
                      SshUInt32 argc, SshAuditArgument argv,
                      SshAuditArgument default_value)
{
  SshUInt32 idx;

  for (idx = 0; idx < argc; idx++)
    {
      if (argv[idx].type == type)
        return &argv[idx];
    }

  return default_value;
}

/* Structure for housing default values for appgw audit events
   copied from the SshAppgwContextStruct. */
typedef struct SshAppgwAuditDefaultsRec
{
  SshUInt8 ipproto_value;
  SshUInt8 src_ip_value[16];
  SshUInt8 dst_ip_value[16];
  SshUInt8 src_port_value[2];
  SshUInt8 dst_port_value[2];
  SshAuditArgumentStruct ipproto;
  SshAuditArgumentStruct src_ip;
  SshAuditArgumentStruct dst_ip;
  SshAuditArgumentStruct src_port;
  SshAuditArgumentStruct dst_port;
  SshAuditArgumentStruct from_tunnel;
  SshAuditArgumentStruct to_tunnel;
} *SshAppgwAuditDefaults, SshAppgwAuditDefaultsStruct;

void
ssh_appgw_audit_init_defaults(SshAppgwAuditDefaults defaults,
                              SshAppgwContext appgw_ctx,
                              SshPmAppgwConn appgw_conn)
{
  SshADTHandle h;
  SshPmTunnel tunnel;
  SshPmTunnelStruct tmp_tunnel;

  defaults->ipproto.type = SSH_AUDIT_IPPROTO;
  defaults->ipproto_value = appgw_conn->ipproto;
  defaults->ipproto.data = &defaults->ipproto_value;
  defaults->ipproto.data_len = 1;

  defaults->src_ip.type = SSH_AUDIT_SOURCE_ADDRESS;
  SSH_IP_ENCODE(&appgw_ctx->initiator_ip, defaults->src_ip_value,
                defaults->src_ip.data_len);
  defaults->src_ip.data = defaults->src_ip_value;

  defaults->dst_ip.type = SSH_AUDIT_DESTINATION_ADDRESS;
  SSH_IP_ENCODE(&appgw_ctx->responder_orig_ip, defaults->dst_ip_value,
                defaults->dst_ip.data_len);
  defaults->dst_ip.data = defaults->dst_ip_value;

  defaults->src_port.type = SSH_AUDIT_SOURCE_PORT;
  SSH_PUT_16BIT(defaults->src_port_value, appgw_ctx->initiator_port);
  defaults->src_port.data = defaults->src_port_value;
  defaults->src_port.data_len = 2;

  defaults->dst_port.type = SSH_AUDIT_DESTINATION_PORT;
  SSH_PUT_16BIT(defaults->dst_port_value, appgw_ctx->responder_orig_port);
  defaults->dst_port.data = defaults->dst_port_value;
  defaults->dst_port.data_len = 2;

  defaults->from_tunnel.type = SSH_AUDIT_FROMTUNNEL_ID;
  defaults->from_tunnel.data = NULL;
  defaults->from_tunnel.data_len = 0;

  defaults->to_tunnel.type = SSH_AUDIT_TOTUNNEL_ID;
  defaults->to_tunnel.data = NULL;
  defaults->to_tunnel.data_len = 0;

  /* Here we make the assumption that SshPmTunnel stays valid
     for the lifetime of SshAppgwAuditDefaults. */
  if (appgw_ctx->from_tunnel_id != 0)
    {
      tmp_tunnel.tunnel_id = appgw_ctx->from_tunnel_id;
      h = ssh_adt_get_handle_to_equal(appgw_conn->pm->tunnels, &tmp_tunnel);
      if (h != SSH_ADT_INVALID)
        {
          tunnel = ssh_adt_get(appgw_conn->pm->tunnels, h);
          SSH_ASSERT(tunnel != NULL);
          defaults->from_tunnel.data = (unsigned char *)tunnel->tunnel_name;
          defaults->from_tunnel.data_len = strlen(tunnel->tunnel_name) + 1;
        }
    }

  if (appgw_ctx->to_tunnel_id != 0)
    {
      tmp_tunnel.tunnel_id = appgw_ctx->to_tunnel_id;
      h = ssh_adt_get_handle_to_equal(appgw_conn->pm->tunnels, &tmp_tunnel);
      if (h != SSH_ADT_INVALID)
        {
          tunnel = ssh_adt_get(appgw_conn->pm->tunnels, h);
          SSH_ASSERT(tunnel != NULL);
          defaults->to_tunnel.data = (unsigned char *)tunnel->tunnel_name;
          defaults->to_tunnel.data_len = strlen(tunnel->tunnel_name) + 1;
        }
    }
}

void
ssh_appgw_audit_event_cb(SshAuditEvent event,
                         SshUInt32 argc,
                         SshAuditArgument argv,
                         void *audit_ctx)
{
  SshAppgwContext ctx = (SshAppgwContext) audit_ctx;
  SshAppgwContext master_ctx;
  SshPmAppgwConn conn = (SshPmAppgwConn) ctx->system_context;
  SshAuditArgument real_argv;
  SshUInt32 real_argc, idx;
  char service_name[512];
  SshAppgwAuditDefaultsStruct adefs;

  /* Now we have each audit event attribute in a nice array, then
     we can see if we have any defaults that are not being overriden. */

  real_argc = 0;
  real_argv = ssh_calloc(argc + 10, sizeof(*real_argv));

  if (real_argv == NULL)
    return;

  /* Log appgw service name and connection id */

  master_ctx = (ctx->master ? ctx->master : ctx);

  if (conn->is_dummy)
    ssh_snprintf(service_name, sizeof(service_name),
                 "service %s",
                 ctx->service_name ? ctx->service_name : "<unnamed>");
  else
    ssh_snprintf(service_name, sizeof(service_name),
                 "service %s session %d",
                 ctx->service_name ? ctx->service_name : "<unnamed>",
                 (int) master_ctx->conn_id);

  real_argv[real_argc].type = SSH_AUDIT_EVENT_SOURCE;
  real_argv[real_argc].data = (unsigned char *)service_name;
  real_argv[real_argc].data_len = strlen(service_name);

  real_argc++;

  if (conn->is_dummy == 0)
    {
      /* Audit ipproto, source ip, destination ip, source port,
         destination port */

      ssh_appgw_audit_init_defaults(&adefs, audit_ctx, conn);

      real_argv[real_argc++] = *ssh_appgw_audit_param(SSH_AUDIT_IPPROTO,
                                                      argc, argv,
                                                      &adefs.ipproto);

      real_argv[real_argc] = *ssh_appgw_audit_param(SSH_AUDIT_FROMTUNNEL_ID,
                                                      argc, argv,
                                                      &adefs.from_tunnel);

      /* ssh_appgw_audit_event_array() does not handle NULL pointers
         very well. Make sure they are overwritten, if we are unable
         to specify FROMTUNNEL_ID or TOTUNNEL_ID */
      if (real_argv[real_argc].data != NULL)
        real_argc++;

      real_argv[real_argc] = *ssh_appgw_audit_param(SSH_AUDIT_TOTUNNEL_ID,
                                                    argc, argv,
                                                    &adefs.to_tunnel);

      if (real_argv[real_argc].data != NULL)
        real_argc++;

      real_argv[real_argc++] = *ssh_appgw_audit_param(SSH_AUDIT_SOURCE_ADDRESS,
                                                      argc, argv,
                                                      &adefs.src_ip);

      real_argv[real_argc++] =
        *ssh_appgw_audit_param(SSH_AUDIT_DESTINATION_ADDRESS,
                               argc, argv, &adefs.dst_ip);

      real_argv[real_argc++] = *ssh_appgw_audit_param(SSH_AUDIT_SOURCE_PORT,
                                                      argc, argv,
                                                      &adefs.src_port);

      real_argv[real_argc++] =
        *ssh_appgw_audit_param(SSH_AUDIT_DESTINATION_PORT,
                               argc, argv, &adefs.dst_port);

    }

  /* Audit all the other parameters we could have been provided. */

  for (idx = 0; idx < argc; idx++)
    {
      if (argv[idx].type == SSH_AUDIT_EVENT_SOURCE
          || argv[idx].type == SSH_AUDIT_IPPROTO
          || argv[idx].type == SSH_AUDIT_FROMTUNNEL_ID
          || argv[idx].type == SSH_AUDIT_TOTUNNEL_ID
          || argv[idx].type == SSH_AUDIT_SOURCE_ADDRESS
          || argv[idx].type == SSH_AUDIT_DESTINATION_ADDRESS
          || argv[idx].type == SSH_AUDIT_SOURCE_PORT
          || argv[idx].type == SSH_AUDIT_DESTINATION_PORT)
        continue;

      real_argv[real_argc++] = argv[idx];
    }

  /* Sanity check. */
  real_argv[real_argc].type = SSH_AUDIT_ARGUMENT_END;

  if (event == SSH_AUDIT_APPGW_SESSION_END)
    ctx->session_end_event_generated = 1;

 {
   SshPmAuditModule module;

   module = conn->pm->audit.modules;
   while (module)
     {
       if (module->audit_subsystems & SSH_PM_AUDIT_APPGW)
         ssh_audit_event_array(module->context, event, real_argc, real_argv);

       module = module->next;
     }
 }

  ssh_free(real_argv);
}

void
ssh_appgw_audit_event(SshAppgwContext ctx,
                      SshAuditEvent event, ...)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) ctx->system_context;
  SshAuditContext format_ctx;
  va_list ap;

  if (conn->should_audit == 0)
    return;

  /* A trick is used to get away the ssh_audit_event() API's problems
     (ie. the SSH_AUDIT_* types specify on a type-by-type basis in the
     var-arg list how the attributes are encoded. This means that we
     depend on the ssh_audit_create() API being *SYNCHRONOUS*.  */

  format_ctx = ssh_audit_create(ssh_appgw_audit_event_cb, NULL_FNPTR, ctx);
  if (format_ctx == NULL)
    return;

  va_start(ap, event);
  ssh_audit_event_va(format_ctx, event, ap);
  va_end(ap);

  ssh_audit_destroy(format_ctx);
}

/* An abort callback for dynamic port open operation of the connection
   `operation_context'. */
static void
ssh_appgw_open_port_abort(void *operation_context)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) operation_context;

  SSH_ASSERT(conn->state == SSH_PM_APPGW_OPEN_PORT);

  /* Mark the operation aborted. */
  conn->aborted = 1;

  /* And set the state to connected. */
  conn->state = SSH_PM_APPGW_CONNECTED;
}

SshOperationHandle
ssh_appgw_open_port(SshAppgwContext ctx,
                    SshAppgwParams params,
                    SshUInt16 src_port, SshUInt16 dst_port,
                    SshUInt32 flags,
                    SshAppgwOpenCB callback, void *context)
{
  SshUInt8 ipproto;
  SshUInt32 flow_timeout;
  SshPmAppgwConn conn = (SshPmAppgwConn) ctx->system_context;

  SSH_ASSERT(conn->state == SSH_PM_APPGW_CONNECTED);

  if (params == NULL)
    {
      ipproto = conn->ipproto;
      flow_timeout = conn->appgw_instance->flow_idle_timeout;

      if (flags & SSH_APPGW_OPEN_FORCED)
        {
          (*callback)(ctx, FALSE, NULL, 0, 0, context);
          return NULL;
        }
    }
  else
    {
      ipproto = (params->ipproto ? params->ipproto : conn->ipproto);
      flow_timeout = (params->flow_idle_timeout
                      ? params->flow_idle_timeout
                      : conn->appgw_instance->flow_idle_timeout);

      if (flags & SSH_APPGW_OPEN_FORCED)
        conn->u.open_port.forced_dst_port = params->forced_port;
    }

  /* Create operation handle. */
  conn->u.open_port.handle = ssh_operation_register(ssh_appgw_open_port_abort,
                                                    conn);
  if (conn->u.open_port.handle == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not register operation handle"));
      (*callback)(ctx, FALSE, NULL, 0, 0, context);
      return NULL;
    }

  conn->u.open_port.ipproto = ipproto;
  conn->u.open_port.src_port = src_port;
  conn->u.open_port.dst_port = dst_port;
  conn->u.open_port.flags = flags;
  conn->u.open_port.callback = callback;
  conn->u.open_port.context = context;
  conn->u.open_port.flow_idle_timeout = flow_timeout;

  conn->state = SSH_PM_APPGW_OPEN_PORT;

  ssh_fsm_continue(&conn->thread);

  return conn->u.open_port.handle;
}


void
ssh_appgw_close_port(SshAppgwContext ctx, SshUInt32 open_port_handle)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) ctx->system_context;

  if (open_port_handle == SSH_IPSEC_INVALID_INDEX)
    return;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("close port %d",
                               (int) open_port_handle));

  /* Delete the rule that implements the port.  This will
     automatically delete all flows created from it. */

  ssh_pme_delete_rule(conn->pm->engine, open_port_handle,
                      NULL_FNPTR, NULL);
}


static void
ssh_appgw_tcp_listener_callback(SshTcpError error, SshStream stream,
                                void *context)
{
  SshPmAppgwInstance appgwi = (SshPmAppgwInstance) context;
  unsigned char src_addr[64];
  unsigned char src_port_buf[8];
  unsigned char dst_addr[64];
  unsigned char dst_port_buf[8];
  SshIpAddrStruct src_ip;
  SshUInt16 src_port;
  SshIpAddrStruct dst_ip;
  SshUInt16 dst_port;
  SshPmAppgwConn *connp;

  if (error != SSH_TCP_NEW_CONNECTION)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Called with error %s",
                             ssh_tcp_error_string(error)));
      return;
    }

  if (!ssh_tcp_get_local_address(stream, dst_addr, sizeof(dst_addr))
      || !ssh_tcp_get_local_port(stream, dst_port_buf, sizeof(dst_port_buf))
      || !ssh_tcp_get_remote_address(stream, src_addr, sizeof(src_addr))
      || !ssh_tcp_get_remote_port(stream, src_port_buf, sizeof(src_port_buf)))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not fetch address or port information of an incoming "
                 "appgw TCP initiator stream: connection ignored"));
      ssh_stream_destroy(stream);
      return;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("New initiator stream: src=%s:%s, dst=%s:%s",
                           src_addr, src_port_buf,
                           dst_addr, dst_port_buf));

  SSH_VERIFY(ssh_ipaddr_parse(&src_ip, src_addr));
  SSH_VERIFY(ssh_ipaddr_parse(&dst_ip, dst_addr));
  src_port = ssh_uatoi(src_port_buf);
  dst_port = ssh_uatoi(dst_port_buf);

  /* Check if we know it. */
  for (connp = &appgwi->pending_connections; *connp; connp = &(*connp)->next)
    {
      SshIpAddrStruct gwip;

      if (SSH_IP_IS6(&dst_ip))
        gwip = (*connp)->appgw_instance->gwip6;
      else
        gwip = (*connp)->appgw_instance->gwip;

      if (SSH_IP_EQUAL(&src_ip, &(*connp)->gw_ip)
          && SSH_IP_EQUAL(&dst_ip, &gwip)
          && src_port == (*connp)->gw_initiator_port
          && dst_port == (*connp)->appgw_instance->gwport)
        {
          SshPmAppgwConn conn = *connp;

          /* Found a match. */
          *connp = conn->next;

          /* Notify application gateway thread about the
             successful intiator stream opening. */
          conn->context.initiator_stream = stream;
          ssh_fsm_continue(&conn->thread);
          return;
        }
    }

  SSH_DEBUG(SSH_D_FAIL, ("Unknown initiator stream"));
  ssh_stream_destroy(stream);
}

/* Create TCP listeners and allocate UDP listener port numbers for the
   local application gateway instance `appgwi'.  The function returns
   TRUE if the listeners were allocated and FALSE otherwise. */
static Boolean
ssh_appgw_create_local_listener(SshPm pm, SshPmAppgw appgw,
                                SshPmAppgwInstance appgwi)
{
  unsigned char local_addr[SSH_IP_ADDR_STRING_SIZE];
  unsigned char local_addr6[SSH_IP_ADDR_STRING_SIZE];

  SSH_ASSERT(appgwi->local);

  if (SSH_IP_DEFINED(&appgwi->gwip))
    ssh_ipaddr_print(&appgwi->gwip, local_addr, sizeof(local_addr));
  if (SSH_IP_DEFINED(&appgwi->gwip6))
    ssh_ipaddr_print(&appgwi->gwip6, local_addr6, sizeof(local_addr6));

  /* Let's create listener for incoming connections. */
  switch (appgw->ipproto)
    {
    case SSH_IPPROTO_TCP:
      {
        SshTcpListenerParamsStruct tcp_params;

        /* Close the possible old TCP listeners. */
        if (appgwi->u.local.tcp_listener)
          {
            ssh_tcp_destroy_listener(appgwi->u.local.tcp_listener);
            appgwi->u.local.tcp_listener = NULL;
          }
        if (appgwi->u.local.tcp_listener6)
          {
            ssh_tcp_destroy_listener(appgwi->u.local.tcp_listener6);
            appgwi->u.local.tcp_listener6 = NULL;
          }

        memset(&tcp_params, 0, sizeof(tcp_params));
        tcp_params.listener_reusable = SSH_TCP_REUSABLE_ADDRESS;
        tcp_params.listen_backlog = SSH_APPGW_INITIATOR_STREAM_BACKLOG;

        /* Pick a random local port. */

        if (pm->appgw_next_local_port == 0
            || pm->appgw_next_local_port > 65533)
          pm->appgw_next_local_port = 1999;

        for (pm->appgw_next_local_port++; ; pm->appgw_next_local_port++)
          {
            unsigned char buf[64];




            ssh_snprintf(ssh_sstr(buf), sizeof(buf),
                         "%u", pm->appgw_next_local_port);
            if (SSH_IP_DEFINED(&appgwi->gwip))
              appgwi->u.local.tcp_listener
                = ssh_tcp_make_listener(local_addr, buf, &tcp_params,
                                        ssh_appgw_tcp_listener_callback,
                                        appgwi);
            if (SSH_IP_DEFINED(&appgwi->gwip6))
              appgwi->u.local.tcp_listener6
                = ssh_tcp_make_listener(local_addr6, buf, &tcp_params,
                                        ssh_appgw_tcp_listener_callback,
                                        appgwi);

            if (appgwi->u.local.tcp_listener || appgwi->u.local.tcp_listener6)
              {
                appgwi->gwport = pm->appgw_next_local_port;
                if (appgwi->u.local.tcp_listener)
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Local TCP listener for appgw `%s' "
                             "running on `%s:%s'",
                             appgw->ident, local_addr, buf));
                if (appgwi->u.local.tcp_listener6)
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Local TCP listener for appgw `%s' "
                             "running on `%s:%s'",
                             appgw->ident, local_addr6, buf));

                /* Let's assume that the next port number is free
                   responder connections.  Actually, it is usable
                   unless someone is listening on it.  On the other
                   hand, even if we checked that it is free now,
                   someone can take it before the connection reaches
                   the application gateway.  So we simply hope that
                   the ports are free when the system starts. */
                pm->appgw_next_local_port++;
                break;
              }

            /* Check if we could not create the TCP listener for any
               unprivileged port (e.g. the `appgw_next_local_port'
               wrapped around). */
            if (pm->appgw_next_local_port == 0)
              {
                SSH_DEBUG(SSH_D_FAIL, ("Could not create TCP listener"));
                return FALSE;
              }
          }
      }
      break;

    case SSH_IPPROTO_UDP:
      /* Pick a random local port. */
      if (pm->appgw_next_local_port == 0
          || pm->appgw_next_local_port > 65533)
        pm->appgw_next_local_port = 1999;

      appgwi->gwport = ++pm->appgw_next_local_port;

      /* Reserve the next port number for the responder listener. */
      pm->appgw_next_local_port++;

#ifdef DEBUG_LIGHT
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Local UDP appgw `%s' running on:", appgw->ident));
      if (SSH_IP_DEFINED(&appgwi->gwip))
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("  %s:%u", local_addr, appgwi->gwport));
      if (SSH_IP_DEFINED(&appgwi->gwip6))
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("  %s:%u", local_addr6, appgwi->gwport));
#endif /* DEBUG_LIGHT */
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  return TRUE;
}


/* Register application gateway. Creates listeners on all interfaces
   at local machine to overcome problems with local stacks ingress
   filtering (e.g. packet coming in from wrong interface) */
void
ssh_appgw_register_local(SshPm pm,
                         SshAppgwParams params,
                         SshUInt32 flags,
                         SshAppgwConnCB conn_callback, void *conn_context,
                         SshAppgwRegCB callback, void *context)
 {
  SshAppgwError error;
  SshPmAppgw appgw;
  SshPmAppgwInstance appgwi;
  SshIpAddr ip = NULL;
  SshIpAddr ip6 = NULL;
  SshUInt32 ifnum;
  const char *ident;
  Boolean retval;
  Boolean registered = FALSE;

  SSH_ASSERT(params != NULL);
  SSH_ASSERT(params->ident != NULL);

  ident = params->ident;

  /* Check the validity of the ipproto. */
  if (params->ipproto != SSH_IPPROTO_TCP && params->ipproto != SSH_IPPROTO_UDP)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Non-TCP/UPD appgws not supported: ipproto=%u",
                             params->ipproto));
      (*callback)(SSH_APPGW_ERROR_NOTFOUND, context);
      return;
    }

  /* Pick an IP address for this application gateway.  We simply take
     the first local IP address that is not a loopback address. */
  for (retval = ssh_pm_interface_enumerate_start(pm, &ifnum);
       retval;
       retval = ssh_pm_interface_enumerate_next(pm, ifnum, &ifnum))
    {
      if (ip == NULL)
        {
          ip = ssh_pm_find_interface_address(pm, ifnum, FALSE, NULL);
          if (ip && SSH_IP_IS_LOOPBACK(ip))
            /* Skip loopback addresses. */
            ip = NULL;
        }
      if (ip6 == NULL)
        {
          ip6 = ssh_pm_find_interface_address(pm, ifnum, TRUE, NULL);
          if (ip6 && (SSH_IP_IS_LOOPBACK(ip6) || SSH_IP6_IS_LINK_LOCAL(ip6)))
            ip6 = NULL;
        }

      if (ip == NULL && ip6 == NULL)
        continue;

      /* Register us to the system. */
      error = ssh_appgw_api_register(pm, params,
                                     flags, ip, ip6,
                                     conn_callback, conn_context,
                                     &appgw, &appgwi);

      if (error != SSH_APPGW_ERROR_OK)
        {
          (*callback)(error, context);
          return;
        }

      /* Ok, we managed to register with the policy manager. */

      appgwi->local = 1;
      appgwi->u.local.ifnum = ifnum;

      /* Let's create listeners for incoming connections. */
      if (!ssh_appgw_create_local_listener(pm, appgw, appgwi))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not create TCP listener"));
          ssh_appgw_unregister_local(pm,
                                     ident,
                                     params->version, params->ipproto);

          (*callback)(SSH_APPGW_ERROR_TOOMANY, context);
          return;
        }
      else
        {
          registered = TRUE;
        }

      ip = ip6 = NULL;
    }
  /* All done. */
  if (registered)
    (*callback)(SSH_APPGW_ERROR_OK, context);
  else
    (*callback)(SSH_APPGW_ERROR_FAILED, context);
}


void
ssh_appgw_unregister_local(SshPm pm, const char *ident, SshUInt32 version,
                           SshUInt8 ipproto)
{
  SshPmAppgw *appgwp;
  SshUInt32 i;

  /* Lookup a local instance of the application gateway
     identification. */
  for (appgwp = &pm->appgws; *appgwp; appgwp = &(*appgwp)->next)
    if (strcmp((*appgwp)->ident, ident) == 0 && (*appgwp)->version == version
        && (*appgwp)->ipproto == ipproto)
      {
        SshPmAppgw appgw = *appgwp;
        SshUInt32 num_valid = 0;

        SSH_DEBUG(SSH_D_NICETOKNOW, ("Unregistering local appgw `%s'", ident));

        for (i = 0; i < SSH_PM_MAX_APPGW_HOSTS; i++)
          if (appgw->hosts[i].valid)
            {
              if (!appgw->hosts[i].local)
                {
                  num_valid++;
                  continue;
                }

              /* Found us.  Uninit this instance. */
              if (appgw->hosts[i].u.local.tcp_listener)
                ssh_tcp_destroy_listener(appgw->hosts[i]
                                         .u.local.tcp_listener);
              if (appgw->hosts[i].u.local.tcp_listener6)
                ssh_tcp_destroy_listener(appgw->hosts[i]
                                         .u.local.tcp_listener6);
            }

        if (num_valid == 0)
          {
            /* This was the last instance of this type. */
            *appgwp = appgw->next;
            ssh_pm_appgw_free(pm, appgw);
          }

        break;
      }

  /* Notify the main thread if the policy manager is shutting
     down and we were the last instance. */
  if (pm->destroyed && pm->appgws == NULL)
    ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
}































/***************** Initializing application gateway module ******************/

static SshUInt32
ssh_pm_appgw_conn_hash(void *ptr, void *ctx)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) ptr;
  SshUInt32 hash = 0;

  hash ^= ssh_ipaddr_hash(&conn->context.initiator_ip);
  hash ^= ssh_ipaddr_hash(&conn->context.responder_orig_ip);
  hash ^= conn->ipproto;
  hash ^= conn->context.from_tunnel_id;
  hash ^= conn->context.to_tunnel_id;
  hash ^= conn->context.initiator_port;
  hash ^= (conn->context.responder_orig_port << 16);

  return hash;
}

static int
ssh_pm_appgw_conn_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshPmAppgwConn c1 = (SshPmAppgwConn) ptr1;
  SshPmAppgwConn c2 = (SshPmAppgwConn) ptr2;

  if (SSH_IP_EQUAL(&c1->context.initiator_ip, &c2->context.initiator_ip)
      && SSH_IP_EQUAL(&c1->context.responder_orig_ip,
                      &c2->context.responder_orig_ip)
      && c1->ipproto == c2->ipproto
      && c1->context.initiator_port == c2->context.initiator_port
      && c1->context.from_tunnel_id == c2->context.from_tunnel_id
      && c1->context.to_tunnel_id == c2->context.to_tunnel_id
      && c1->context.responder_orig_port == c2->context.responder_orig_port)
    return 0;

  return -1;
}

Boolean
ssh_pm_appgw_init(SshPm pm)
{





























  pm->appgw_pending_conn_requests
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshPmAppgwConnStruct,
                                               adt_header),

                             SSH_ADT_HASH,      ssh_pm_appgw_conn_hash,
                             SSH_ADT_COMPARE,   ssh_pm_appgw_conn_compare,
                             SSH_ADT_CONTEXT,   pm,

                             SSH_ADT_ARGS_END);
  if (pm->appgw_pending_conn_requests == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not create ADT bag for pending connection requests"));





      return FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Application gateway protocol running on port %s",
             pm->params.appgw_port));

  return TRUE;
}


void
ssh_pm_appgw_uninit(SshPm pm)
{








  SSH_ASSERT(pm->appgws == NULL);

  if (pm->appgw_pending_conn_requests)
    {
      ssh_adt_destroy(pm->appgw_pending_conn_requests);
      pm->appgw_pending_conn_requests = NULL;
    }
}

/* Handle the interface change for all application gateways. */
void
ssh_pm_appgw_interface_change(SshPm pm)
{
  Boolean found = FALSE;
  SshUInt32 ifnum, i, x;
  int error;
  SshIpAddr ip;
  SshPmAppgw appgw, tmp_appgw;
  Boolean retval;
  SshPmAppgwInstance appgwi;

  /* Remove the disappeared listeners. */
  for (appgw = pm->appgws; appgw; appgw = appgw->next)
    for (i = 0; i < SSH_PM_MAX_APPGW_HOSTS; i++)
      if (appgw->hosts[i].valid &&
         (!ssh_pm_find_interface_by_address(pm, &appgw->hosts[i].gwip, NULL) &&
          !ssh_pm_find_interface_by_address(pm, &appgw->hosts[i].gwip6, NULL)))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Removing appgw listener for %@",
                                     ssh_ipaddr_render, appgw->hosts[i].gwip));

          if (appgw->hosts[i].u.local.tcp_listener)
            ssh_tcp_destroy_listener(appgw->hosts[i].u.local.tcp_listener);

          if (appgw->hosts[i].u.local.tcp_listener6)
            ssh_tcp_destroy_listener(appgw->hosts[i].u.local.tcp_listener6);

          appgw->hosts[i].u.local.tcp_listener = NULL;
          appgw->hosts[i].u.local.tcp_listener6 = NULL;
          appgw->hosts[i].valid = 0;
        }

  /* Add the new listeners, also if we failed to start on the previous round
     a listener, try to start it again. */
  for (retval = ssh_pm_interface_enumerate_start(pm, &ifnum);
       retval;
       retval = ssh_pm_interface_enumerate_next(pm, ifnum, &ifnum))
    {
      SshInterceptorInterface *ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);
      if (ifp == NULL)
        continue;

      /* Iterate all the IP addresses on one interface. */
      for (x = 0; x < ifp->num_addrs; x++)
        {
          SshInterfaceAddress addr = &ifp->addrs[x];

          /* Accept only IP protocols. */
          if (addr->protocol != SSH_PROTOCOL_IP4 &&
              addr->protocol != SSH_PROTOCOL_IP6)
            continue;

          /* Skip loopback and link local addresses. */
          ip = &addr->addr.ip.ip;
          if (!ip || SSH_IP_IS_LOOPBACK(ip) || SSH_IP6_IS_LINK_LOCAL(ip))
            continue;

          /* Go through all the appgw's. Update the one's which does not
             have the listener already. */
          for (appgw = pm->appgws; appgw; appgw = appgw->next)
            {
              found = FALSE;

              for (i = 0; i < SSH_PM_MAX_APPGW_HOSTS; i++)
                {
                  if(appgw->hosts[i].valid &&
                     (SSH_IP_EQUAL(&appgw->hosts[i].gwip, ip) ||
                      SSH_IP_EQUAL(&appgw->hosts[i].gwip6, ip)))
                    {
                      found = TRUE;

                      /* Check if we have failed to create TCP listeners in
                         the previous interface update. */
                      if (appgw->ipproto == SSH_IPPROTO_TCP
                          && (appgw->hosts[i].u.local.tcp_listener == NULL
                              && appgw->hosts[i].u.local.tcp_listener6
                              == NULL))
                        {
                          SSH_DEBUG(SSH_D_NICETOKNOW,
                                    ("Retrying TCP listener creation"));
                          (void) ssh_appgw_create_local_listener(pm, appgw,
                                                                 &appgw->
                                                                 hosts[i]);
                        }

                      break;
                    }
                }

              if (appgw && found == FALSE)
                {
                  /* Update the IP addresses. */
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Updating appgw IP addresses to %@",
                             ssh_ipaddr_render, ip));

                  error = ssh_appgw_api_register(pm,
                                                 &appgw->appgw_conn_params,
                                                 appgw->conn_flags,
                                                 SSH_IP_IS6(ip) ? NULL : ip,
                                                 SSH_IP_IS6(ip) ? ip : NULL,
                                                 appgw->conn_callback,
                                                 appgw->conn_context,
                                                 &tmp_appgw, &appgwi);

                  if (error != SSH_APPGW_ERROR_OK)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Appgw interface registration failed."));
                      continue;
                    }

                  appgwi->local = 1;
                  appgwi->u.local.ifnum = ifnum;

                  /* Recreate TCP and UDP listeners. */
                  (void) ssh_appgw_create_local_listener(pm, appgw,
                                                         appgwi);
                }
            }
        }
    }
}


/**************** Handling notifications to existing appgw's ****************/

SshPmAppgwConn
ssh_pm_appgw_find_conn_and_remove(SshPm pm,
                                  SshUInt32 flow_index)
{
  SshPmAppgwConn conn;
  SshPmAppgwConn *iter;
  size_t kh;

  SSH_ASSERT(pm != NULL);

  if (flow_index == SSH_IPSEC_INVALID_INDEX)
    return NULL;

  kh = flow_index % SSH_APPGW_FLOW_HASH_SIZE;

  iter = &pm->flow_map_i[kh];
  while (*iter)
    {
      if ((*iter)->initiator_flow_index == flow_index)
        {
          conn=*iter;
          *iter=(*iter)->flow_map_i_next;
          return conn;
        }

      iter = &((*iter)->flow_map_i_next);
    }

  iter = &pm->flow_map_r[kh];
  while (*iter)
    {
      if ((*iter)->responder_flow_index == flow_index)
        {
          conn=*iter;
          *iter=(*iter)->flow_map_r_next;
          return conn;
        }
      iter = &((*iter)->flow_map_r_next);
    }
  return NULL;
}

void
ssh_pm_appgw_flow_free_notification(SshPm pm,
                                    SshUInt32 flow_index)
{
  SshPmAppgwConn conn;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("received flow free notification for flow index %d",
             (int) flow_index));

  conn = ssh_pm_appgw_find_conn_and_remove(pm, flow_index);

  if (conn == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("no valid appgw found for flow index %d",
                 (int) flow_index));
      return;
    }

  /* Send signal to this appgw */
  conn->flow_invalid = 1;
  if (conn->is_waiting_for_continue)
    ssh_fsm_continue(&conn->thread);
}

/**************** Handling new application gateway requests *****************/

static void
ssh_pm_appgw_thread_destructor(SshFSM fsm, void *context)
{
  SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);
  SshPmAppgwConn conn = (SshPmAppgwConn) context;

  if (conn)
    ssh_pm_appgw_connection_free(pm, conn);
}

void
ssh_appgw_create_totunnel_rule(SshPm pm,
                               const SshEnginePolicyRule basis,
                               SshUInt32 trd_index,
                               Boolean is_new_session,
                               SshPmeAddRuleCB callback,
                               void *context)
{
  SshEnginePolicyRuleStruct engine_rule;

  SSH_ASSERT(basis != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("creating totunnel rule for basis rule %d",
             (int) basis->rule_index));

  engine_rule = *basis;
  engine_rule.depends_on = basis->rule_index;

  SSH_ASSERT(basis->type == SSH_ENGINE_RULE_TRIGGER);
  SSH_ASSERT(trd_index != SSH_IPSEC_INVALID_INDEX);

  if (basis->flags & SSH_PM_ENGINE_RULE_APPGW)
    engine_rule.type = SSH_ENGINE_RULE_TRIGGER;
  else
    {
      SSH_ASSERT(basis->flags & SSH_PM_ENGINE_RULE_SLAVE);
      engine_rule.type = SSH_ENGINE_RULE_APPLY;
    }

  if (!is_new_session && (engine_rule.flags & SSH_ENGINE_RULE_USE_ONCE))
    engine_rule.flags |= SSH_ENGINE_RULE_USED;

  engine_rule.flags |= SSH_PM_ENGINE_RULE_APPGW;

  engine_rule.transform_index = trd_index;
  engine_rule.precedence = basis->precedence + 1;

  engine_rule.flags &= ~SSH_ENGINE_RULE_UNDEFINED;
  engine_rule.flags &= ~SSH_ENGINE_RULE_INACTIVE;

  ssh_pme_add_rule(pm->engine, FALSE, &engine_rule, callback, context);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("appgw totunnel rule has been created"));
}

/* This function selects the appgw instance */
void
ssh_pm_appgw_request(SshPm pm, SshPmRule rule,
                     SshPmService service, SshPmAppgwConn master_connection,
                     SshUInt32 rule_index,
                     SshUInt32 flow_index,
                     SshInterceptorProtocol protocol, SshUInt32 ifnum,
                     SshUInt32 flags,
                     SshUInt32 trigger_rule_index,
                     SshUInt32 from_tunnel_id,
                     SshUInt32 to_tunnel_id,
                     SshUInt32 transform_index,
                     SshUInt32 prev_transform_index,
                     SshIpAddr packet_src, SshIpAddr packet_dst,
                     SshInetIPProtocolID packet_ipproto,
                     SshUInt16 packet_src_port, SshUInt16 packet_dst_port,
                     SshIpAddr packet_nat_dst, SshUInt16 packet_nat_dst_port,
                     unsigned char *packet, size_t packet_len)
{
  SshPmAppgwConnStruct conn_struct;
  SshPmAppgwConn conn = NULL;
  SshPmAppgw appgw;
  SshPmAppgwInstance appgwi;
  SshUInt32 i;
  SshUInt32 best_load = 0xffffffff;
  SshUInt32 best_index = 0xffffffff;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("New application gateway request for `%s': "
             "%@.%d > %@.%d (nat: %@.%d) %s ft=0x%08lx tt=0x%08lx",
             service->appgw_ident,
             ssh_ipaddr_render, packet_src, packet_src_port,
             ssh_ipaddr_render, packet_dst, packet_dst_port,
             ssh_ipaddr_render, (packet_nat_dst ? packet_nat_dst : packet_dst),
             (packet_nat_dst ? packet_nat_dst_port : packet_dst_port),
             ssh_find_keyword_name(ssh_ip_protocol_id_keywords,
                                   packet_ipproto),
             (unsigned long) from_tunnel_id,
             (unsigned long) to_tunnel_id));
  SSH_DEBUG(SSH_D_MIDSTART,
            ("Packet attributes: trigger_rule=0x%x, tunnel_id=0x%08lx, "
             "trd_index=0x%x, prev_trd_index=0x%x",
             (unsigned int) trigger_rule_index,
             (unsigned long) from_tunnel_id,
             (unsigned int) transform_index,
             (unsigned int) prev_transform_index));
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Packet:"), packet, packet_len);

  if (rule_index == SSH_IPSEC_INVALID_INDEX
      || flow_index == SSH_IPSEC_INVALID_INDEX)
    goto error;

  if (flags & SSH_PME_PACKET_MEDIABCAST)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("received a broadcast packet as a trigger. discarding."));
      goto error;
    }

  if (protocol == SSH_PROTOCOL_IP4 && packet_ipproto == SSH_IPPROTO_TCP)
    {
      SshUInt32 hlen;
      SshUInt16 tcp_flags;

      hlen = SSH_IPH4_HLEN(packet) << 2;

      if (hlen + SSH_TCPH_HDRLEN > packet_len)
        goto error;

      tcp_flags = SSH_TCPH_FLAGS(packet+hlen);

      if ((tcp_flags & SSH_TCPH_FLAG_SYN) == 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("TCP trigger packet did not contain SYN flag, "
                     "discarding"));
          goto error;
        }
    }





  /* Check if it is already active. */
  memset(&conn_struct, 0, sizeof(conn_struct));
  conn_struct.context.initiator_ip = *packet_src;
  conn_struct.context.initiator_port = packet_src_port;
  conn_struct.context.responder_orig_ip = *packet_dst;
  conn_struct.context.responder_orig_port = packet_dst_port;
  conn_struct.context.from_tunnel_id = from_tunnel_id;
  conn_struct.context.to_tunnel_id = to_tunnel_id;
  conn_struct.ipproto = packet_ipproto;

  if (ssh_adt_get_handle_to_equal(pm->appgw_pending_conn_requests,
                                  &conn_struct) != SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Connection request already active"));
      goto error;
    }

  /* Do we know this application gateway identification? */
  for (appgw = pm->appgws; appgw; appgw = appgw->next)
    if (strcmp(appgw->ident, service->appgw_ident) == 0
        && appgw->ipproto == packet_ipproto)
      break;

  if (appgw == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Application gateway not registered"));
      goto error;
    }

  /* Allocate a new connection. */
  conn = ssh_pm_appgw_connection_alloc(pm);
  if (conn == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate new connection request"));
      goto error;
    }

  conn->pm = pm;
  conn->context.initiator_ip = *packet_src;
  conn->context.initiator_port = packet_src_port;
  conn->context.responder_orig_ip = *packet_dst;
  conn->context.responder_orig_port = packet_dst_port;
  conn->should_audit = (rule != NULL
                        ?  (rule->flags & SSH_PM_RULE_LOG ? 1 : 0)
                        : 0);
  conn->initiator_flow_index = flow_index;
  conn->responder_flow_index = flow_index;

  if (master_connection)
    conn->context.conn_id = master_connection->context.conn_id;
  else
    conn->context.conn_id = pm->appgw_session_id++;

  if (packet_nat_dst)
    {
      /* This is an SSH_APPGW_OPEN_THISGW connection to private
         network. */
      conn->context.responder_ip = *packet_nat_dst;
      conn->context.responder_port = packet_nat_dst_port;
    }
  else
    {
      /* A normal application gateway connection. */
      conn->context.responder_ip = *packet_dst;
      conn->context.responder_port = packet_dst_port;
    }

  conn->context.service_id = service->unique_id;

  conn->ipproto = packet_ipproto;
  conn->trigger_rule_index = trigger_rule_index;

  SSH_ASSERT(conn->trigger_rule_index != SSH_IPSEC_INVALID_INDEX);

  conn->u.init.current_rule_index = rule_index;
  conn->u.init.protocol = protocol;
  conn->u.init.ifnum = ifnum;
  conn->u.init.flags = flags;
  conn->u.init.from_tunnel_id = from_tunnel_id;
  conn->u.init.to_tunnel_id = to_tunnel_id;
  conn->u.init.transform_index = transform_index;
  conn->u.init.prev_transform_index = prev_transform_index;
  conn->u.init.packet = packet;
  conn->u.init.packet_len = packet_len;

  if (master_connection)
    conn->context.master = &master_connection->context;
  conn->context.system_context = conn;
  conn->rule = rule;

  /* Pick one server. */
  for (i = 0; i < SSH_PM_MAX_APPGW_HOSTS; i++)
    {
      if (appgw->hosts[i].local &&
          appgw->hosts[i].u.local.ifnum != ifnum)
        continue;

      if (appgw->hosts[i].valid && appgw->hosts[i].load < best_load)
        {
          if (SSH_IP_IS4(packet_src) &&
              !SSH_IP_DEFINED(&appgw->hosts[i].gwip))
            continue;
          if (SSH_IP_IS6(packet_src) &&
              !SSH_IP_DEFINED(&appgw->hosts[i].gwip6))
            continue;
          best_load = appgw->hosts[i].load;
          best_index = i;
        }
    }

  if (best_load == 0xffffffff)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No application gateway host found for `%s'",
                             appgw->ident));
      goto error;
    }

  appgwi = &appgw->hosts[best_index];

  appgwi->num_connections++;
  conn->appgw = appgw;
  conn->appgw_instance = appgwi;
  conn->u.init.flow_idle_timeout = appgwi->flow_idle_timeout;
  conn->context.service_name = NULL;
  conn->context.service_id = service->unique_id;
  if (service->service_name)
    {
      /* Cache these into the connection for logging */
      conn->context.service_name = ssh_strdup(service->service_name);
      if (conn->context.service_name == NULL)
        goto error;
    }

  /* Does the instance already know this service? */
  for (i = 0; i < SSH_PM_MAX_SERVICES; i++)
    if (appgwi->service_ids[i] == service->unique_id)
      {
        /* Service known. */
        break;
      }
    else if (appgwi->service_ids[i] == 0)
      {
        SshAppgwContext ctx_struct;

        /* End of services reached.  Register this new service
           object. */
        appgwi->service_ids[i] = service->unique_id;

        /* Notify application gateway instance about service's
           configuration data. */

        ctx_struct = &conn_struct.context;
        memset(&conn_struct, 0, sizeof(conn_struct));
        ctx_struct->service_name = service->service_name;
        ctx_struct->service_id = service->unique_id;
        ctx_struct->config_data = service->appgw_config;
        ctx_struct->config_data_len = (service->appgw_config != NULL
                                       ?service->appgw_config_len:0);
        ctx_struct->audit_event_generated = 0;
        ctx_struct->system_context = (void*)&conn_struct;
        conn_struct.pm = pm;
        conn_struct.is_dummy = 1;
        conn_struct.should_audit = 1;

        SSH_DEBUG(SSH_D_LOWOK,
                  ("Updating config data of "
                   "appgw %s %@:%d (service ID %u NAME %s)",
                   appgw->ident,
                   ssh_ipaddr_render, &appgwi->gwip,
                   (int) appgwi->gwport,
                   (unsigned int) service->unique_id,
                   (service->service_name != NULL ?
                    service->service_name : "(null)")));

        (*appgwi->conn_callback)(ctx_struct,
                                 SSH_APPGW_UPDATE_CONFIG,
                                 NULL, 0,
                                 appgwi->conn_context);

        if (ctx_struct->audit_event_generated == 0)
          ssh_appgw_audit_event(ctx_struct, SSH_AUDIT_NEW_CONFIGURATION,
                                SSH_AUDIT_ARGUMENT_END);
        break;
      }





  /* Now we have one more connection pending. */
  ssh_adt_insert(pm->appgw_pending_conn_requests, conn);

  /* Start a thread to handle the connection. */
  ssh_fsm_thread_init(&pm->fsm, &conn->thread, ssh_pm_st_appgw_start,
                      NULL_FNPTR, ssh_pm_appgw_thread_destructor, conn);
  ssh_fsm_set_thread_name(&conn->thread, "APPGW");
  /* All done. */
  return;

  /* Error handling. */
 error:

  SSH_DEBUG(SSH_D_FAIL, ("Failed to process appgw request!"));
  if (conn)
    ssh_pm_appgw_connection_free(pm, conn);
  /* We must consume the triggered packet. */
  ssh_free(packet);
}

#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
