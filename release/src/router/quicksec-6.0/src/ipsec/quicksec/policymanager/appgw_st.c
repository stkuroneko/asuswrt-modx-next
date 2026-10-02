/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The application gateway thread handling application gateway
   protocol.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

#define SSH_DEBUG_MODULE "SshPmStAppgw"

/************************** Static help functions ***************************/

/* A callback function that is called to notify the success of the
   creation of the application gateway mappings. */
static void
ssh_pm_appgw_mappings_cb(SshPm pm,
                         const SshIpAddr gw_ip,
                         SshUInt16 gw_initiator_port,
                         SshUInt16 gw_responder_port,
                         SshUInt32 initiator_flow_index,
                         SshUInt32 responder_flow_index,
                         const SshIpAddr initiator_ip_after_nat,
                         SshUInt16 initiator_port_after_nat,
                         const SshIpAddr responder_ip_after_nat,
                         SshUInt16 responder_port_after_nat,
                         void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmAppgwConn conn = (SshPmAppgwConn) ssh_fsm_get_tdata(thread);
  SshPmAppgwConn prev;
  size_t ki,kr;

  if (gw_ip == NULL)
    {
      /* Failed to create application gateway mappings. */
      SSH_IP_UNDEFINE(&conn->gw_ip);
      conn->initiator_flow_index = SSH_IPSEC_INVALID_INDEX;
      conn->responder_flow_index = SSH_IPSEC_INVALID_INDEX;
    }
  else
    {
      /* Managed to create mappings. */
      conn->gw_ip = *gw_ip;
      conn->gw_initiator_port = gw_initiator_port;
      conn->gw_responder_port = gw_responder_port;
      conn->initiator_flow_index = initiator_flow_index;
      conn->responder_flow_index = responder_flow_index;

      /* Update appgw context. */
      conn->context.initiator_ip_after_nat = *initiator_ip_after_nat;
      conn->context.initiator_port_after_nat = initiator_port_after_nat;
      conn->context.responder_ip_after_nat = *responder_ip_after_nat;
      conn->context.responder_port_after_nat = responder_port_after_nat;

      prev = ssh_pm_appgw_find_conn_and_remove(pm, initiator_flow_index);
      if (prev != NULL)
        {
          prev->flow_invalid = 1;
          if (prev->is_waiting_for_continue)
            ssh_fsm_continue(&prev->thread);
        }

      prev = ssh_pm_appgw_find_conn_and_remove(pm, responder_flow_index);
      if (prev != NULL)
        {
          prev->flow_invalid = 1;
          if (prev->is_waiting_for_continue)
            ssh_fsm_continue(&prev->thread);
        }

      /* Add new flows to the mapping after old flows have been removed */

      SSH_DEBUG(SSH_D_MY,
                ("appgw connection cached: init flow_index=%d "
                 "resp flow_index=%d",
                 (int) initiator_flow_index,
                 (int) responder_flow_index));

      if (initiator_flow_index != SSH_IPSEC_INVALID_INDEX)
        {
          ki = initiator_flow_index % SSH_APPGW_FLOW_HASH_SIZE;
          conn->flow_map_i_next = pm->flow_map_i[ki];
          pm->flow_map_i[ki] = conn;
        }

      if (responder_flow_index != SSH_IPSEC_INVALID_INDEX)
        {
          kr = responder_flow_index % SSH_APPGW_FLOW_HASH_SIZE;
          conn->flow_map_r_next = pm->flow_map_r[kr];
          pm->flow_map_r[kr] = conn;
        }
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function that is called to notify the success of the
   responder TCP stream creation. */
static void
ssh_pm_appgw_responder_tcp_connect_cb(SshTcpError error,
                                      SshStream stream,
                                      void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmAppgwConn conn = (SshPmAppgwConn) ssh_fsm_get_tdata(thread);

  if (error != SSH_TCP_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create responder stream: %s (%u)",
                             ssh_tcp_error_string(error),error));
      conn->context.responder_stream = NULL;
      if (error != SSH_TCP_TIMEOUT)
        conn->flow_reject = 1;
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Responder stream opened"));
      conn->context.responder_stream = stream;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Let the TCP/UDP initiator flow be opened */
static void
ssh_pm_appgw_i_flow_enabled(SshPm pm, Boolean status, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Initiator flow mode has now been set."));

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A timeout function that is used to retransmit the initiator stream
   opening packet. */
static void
ssh_pm_appgw_process_packet_timeout(void *context)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) context;

  ssh_fsm_continue(&conn->thread);
}

/* An UDP callback function for initiator and responder packets of the
   application gateway connection `conn'.  The argument `action'
   describes whether the packet is coming from the initiator or from
   the responder. */
static void
ssh_pm_appgw_udp_callback(SshUdpListener listener, SshPmAppgwConn conn,
                          SshAppgwAction action)
{
  SshUdpError error;
  size_t datagram_len;

  /* Read one packet. */
  error = ssh_udp_read(listener, NULL, 0, NULL, 0,
                       conn->pm->datagram, sizeof(conn->pm->datagram),
                       &datagram_len);

  /* If the connection is no longer active, ignore this message */
  if (conn->state == SSH_PM_APPGW_DONE)
    return;

  if (error == SSH_UDP_OK)
    (*conn->appgw_instance->conn_callback)(&conn->context,
                                           action,
                                           conn->pm->datagram, datagram_len,
                                           conn->appgw_instance->conn_context);
  else if (error == SSH_UDP_NO_DATA)
    ;
  else
    SSH_DEBUG(SSH_D_FAIL, ("UDP read failed: %s",
                           ssh_udp_error_string(error)));
}

/* A callback function for initiator UDP listener of the application
   gateway conection `context'. */
static void
ssh_pm_appgw_udp_i_callback(SshUdpListener listener, void *context)
{
  ssh_pm_appgw_udp_callback(listener, context,
                            SSH_APPGW_UDP_PACKET_FROM_INITIATOR);
}

/* A callback function for responder UDP listener of the application
   gateway conection `context'. */
static void
ssh_pm_appgw_udp_r_callback(SshUdpListener listener, void *context)
{
  ssh_pm_appgw_udp_callback(listener, context,
                            SSH_APPGW_UDP_PACKET_FROM_RESPONDER);
}

/* Create dynamically opened port of the application gateway
   connection `conn' into an engine rule `rule'. */
static void
ssh_pm_appgw_make_dynamic_port_rule(SshPmAppgwConn conn,
                                    SshEnginePolicyRule rule)
{
  size_t len;
  SshIpAddr src, dst;
  Boolean do_src_nat, do_dst_nat;
  SshPmAppgwInstance appgwi;
  SshUInt32 from_tunnel_id;

  SSH_ASSERT(conn->rule != NULL);

  memset(rule, 0, sizeof(*rule));

  appgwi = conn->appgw_instance;

  rule->depends_on = conn->trigger_rule_index;
  rule->precedence = SSH_PM_RULE_PRI_HIGH;

  /* These are meaningless for trigger rules (the flow idle timeout
     is set via appgw_mappings()), but they are valid for
     dynamically created rules/ports. */
  rule->flow_idle_datagram_timeout = appgwi->flow_idle_timeout;
  rule->flow_idle_session_timeout = appgwi->flow_idle_timeout;

  from_tunnel_id = 0;
  do_src_nat = FALSE;
  do_dst_nat = FALSE;

  SSH_DEBUG(SSH_D_MIDOK,
            ("CONN: I=%@:%d I-n=%@:%d R=%@:%d R-n=%@:%d R-o=%@:%d"
             "(i-nat=%d r-nat=%d) %s",
             ssh_ipaddr_render, &conn->context.initiator_ip,
             conn->context.initiator_port,

             ssh_ipaddr_render, &conn->context.initiator_ip_after_nat,
             conn->context.initiator_port_after_nat,

             ssh_ipaddr_render, &conn->context.responder_ip,
             conn->context.responder_port,

             ssh_ipaddr_render, &conn->context.responder_ip_after_nat,
             conn->context.responder_port_after_nat,

             ssh_ipaddr_render, &conn->context.responder_orig_ip,
             conn->context.responder_orig_port,

             conn->initiator_nat, conn->responder_nat,
             (conn->u.open_port.flags & SSH_APPGW_OPEN_FROM_INITIATOR)
             ? "I" : "R"));

  /* Check the direction of the port opening. */
  if (conn->u.open_port.flags & SSH_APPGW_OPEN_FROM_INITIATOR)
    {
      /* The session is started from the initiator. */

      /* Source selector address */
      src = &conn->context.initiator_ip;

      /* Destination selector address */
      conn->u.open_port.port_dst_ip = conn->context.responder_orig_ip;

      /* NAT destination address */
      dst = &conn->context.responder_ip_after_nat;

      /* Is there need for destination or source NAT? */
      if (conn->responder_nat)
        do_dst_nat = TRUE;

      if (conn->initiator_nat)
        do_src_nat = TRUE;

      if (conn->rule->side_from.tunnel != NULL)
        from_tunnel_id = conn->rule->side_from.tunnel->tunnel_id;

      rule->flags |= SSH_PM_ENGINE_RULE_FORWARD;
    }
  else
    {
      /* The session is started from the responder. */

      /* Source selector address */
      src = &conn->context.responder_ip_after_nat;

      /* Destination selector address */
      conn->u.open_port.port_dst_ip = conn->context.initiator_ip_after_nat;

      /* NAT destination address */
      dst = &conn->context.initiator_ip;

      /* Is there need for destination or source NAT? */
      if (conn->initiator_nat)
        do_dst_nat = TRUE;

      if (conn->responder_nat)
        do_src_nat = TRUE;

      if (conn->rule->side_to.tunnel != NULL)
        from_tunnel_id = conn->rule->side_to.tunnel->tunnel_id;
    }

  if (SSH_IP_IS4(src))
    rule->protocol = SSH_PROTOCOL_IP4;
  else
    rule->protocol = SSH_PROTOCOL_IP6;

  /* Source IP address. */
  SSH_IP_ENCODE(src, rule->src_ip_low, len);
  SSH_IP_ENCODE(src, rule->src_ip_high, len);
  rule->selectors |= SSH_SELECTOR_SRCIP;

  /* Source port if it is specified. */
  if (conn->u.open_port.src_port)
    {
      rule->src_port_low = conn->u.open_port.src_port;
      rule->src_port_high = conn->u.open_port.src_port;
      rule->selectors |= SSH_SELECTOR_SRCPORT;
    }

  /* Destination IP address. */

  SSH_IP_ENCODE(&conn->u.open_port.port_dst_ip, rule->dst_ip_low, len);
  SSH_IP_ENCODE(&conn->u.open_port.port_dst_ip, rule->dst_ip_high, len);
  rule->selectors |= SSH_SELECTOR_DSTIP;

  /* Destination port if specified. */
  if (conn->u.open_port.port_dst_port)
    {
      rule->dst_port_low = conn->u.open_port.port_dst_port;
      rule->dst_port_high = conn->u.open_port.port_dst_port;
      rule->selectors |= SSH_SELECTOR_DSTPORT;
    }

  /* IP protocol. */
  rule->ipproto = conn->u.open_port.ipproto;
  rule->selectors |= SSH_SELECTOR_IPPROTO;

  /* The type of the rule.  Also some of rule's flags and its policy
     context depend on its type. */
  rule->flags |= SSH_PM_ENGINE_RULE_SLAVE;

  rule->transform_index = SSH_IPSEC_INVALID_INDEX;
  rule->type = SSH_ENGINE_RULE_PASS;
  /* This is corrected later by the caller */

  /* Tunnel which we must come from. */
  rule->tunnel_id = from_tunnel_id;

  /* Rule flags. */
  if ((conn->u.open_port.flags & SSH_APPGW_OPEN_MULTIPLE) == 0)
    rule->flags |= SSH_ENGINE_RULE_USE_ONCE;

  /* Is there a NAT at the destination direction? */
  if (do_dst_nat)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("open/port-dst-ip=%@:%d dst=%@:%d",
                 ssh_ipaddr_render, &conn->u.open_port.port_dst_ip,
                 conn->u.open_port.forced_dst_port,
                 ssh_ipaddr_render, dst,
                 conn->u.open_port.dst_port));

      /* Need to NAT selector, if outgoing port number is still unknown */
      if (conn->u.open_port.port_dst_port == 0)
        {
          /* Allocate a port for the destination selector */
          rule->nat_selector_dst_ip = conn->u.open_port.port_dst_ip;
          if (conn->u.open_port.flags & SSH_APPGW_OPEN_FORCED)
            rule->nat_selector_dst_port = conn->u.open_port.forced_dst_port;
          else
            rule->nat_selector_dst_port = 0;
        }

      /* Set the destination NAT IP and port */
      rule->nat_dst_ip_low = *dst;
      rule->nat_dst_ip_high = *dst;
      rule->nat_dst_port = conn->u.open_port.dst_port;
      rule->nat_flags = SSH_PM_NAT_OVERLOAD_PORT;

      SSH_DEBUG(SSH_D_MIDOK,
                ("nat-dst-selector %@:%d nat-dst %@:%d",
                 ssh_ipaddr_render, &rule->nat_selector_dst_ip,
                 rule->nat_selector_dst_port,
                 ssh_ipaddr_render, &rule->nat_dst_ip_low,
                 rule->nat_dst_port));

      rule->flags |= SSH_ENGINE_RULE_FORCE_NAT_DST;
    }

  /* Is there a NAT at the source direction? Only do this for forced NAT,
     dynamic NAT does not need any extra tweaking on source side */
  if (do_src_nat)
    {
      if (conn->u.open_port.flags & SSH_APPGW_OPEN_FROM_INITIATOR)
        {
          /* Opened from initiator side.
             Check that forced source NAT was in use */
          if (SSH_IP_DEFINED(&conn->rule->nat_src_low))
            {
              /* Copy the initiator NATed IP address from context */
              rule->nat_src_ip_low = conn->context.initiator_ip_after_nat;
              rule->nat_src_ip_high = conn->context.initiator_ip_after_nat;

              rule->flags |= SSH_ENGINE_RULE_FORCE_NAT_SRC;
            }
        }
      else
        {
          /* Opened from responder side.
             Check that forced destination NAT was in use */
          if (SSH_IP_DEFINED(&conn->rule->nat_dst_low))
            {
              /* Copy the original responder IP address from context */
              rule->nat_src_ip_low = conn->context.responder_orig_ip;
              rule->nat_src_ip_high = conn->context.responder_orig_ip;

              rule->flags |= SSH_ENGINE_RULE_FORCE_NAT_SRC;
            }
        }
    }

  /* Do not allow flows to change from this rule. */
  rule->flags |= SSH_PM_ENGINE_RULE_FLOW_REF;

  /* Require a notification when flows expire. */
  rule->flags |= SSH_PM_ENGINE_RULE_REPORT;
}

/* A callback function that is called to notify the status of engine
   rule addition. */
static void
ssh_pm_appgw_add_rule_cb(SshPm pm, SshUInt32 ind,
                         const SshEnginePolicyRule rule,
                         void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmAppgwConn conn = (SshPmAppgwConn) ssh_fsm_get_tdata(thread);

  if (conn->u.open_port.rule_index == SSH_IPSEC_INVALID_INDEX)
    conn->u.open_port.rule_index = ind;


  /* Cache last received valid NAT port */
  if (rule && rule->nat_selector_dst_port)
    conn->u.open_port.port_dst_alloc = rule->nat_selector_dst_port;

  if (ind == SSH_IPSEC_INVALID_INDEX)
    conn->failed = 1;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("appgw dynamic port rule added index=%d port_dst_port=%d",
             (int) ind,
             conn->u.open_port.port_dst_port));

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/******************** Application gateway thread states *********************/

SSH_FSM_STEP(ssh_pm_st_appgw_start)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;

  /* Does the application gateway want to redirect the connection. */
  if (conn->appgw_instance->flags & SSH_APPGW_F_REDIRECT)
    {
      /* Yes. */
      SSH_DEBUG(SSH_D_HIGHSTART, ("Calling redirection callback"));
      conn->state = SSH_PM_APPGW_REDIRECT;
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_mappings);
      SSH_FSM_ASYNC_CALL(
        (*conn->appgw_instance->conn_callback)(
                                        &conn->context,
                                        SSH_APPGW_REDIRECT,
                                        NULL, 0,
                                        conn->appgw_instance->conn_context));
      SSH_NOTREACHED;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_mappings);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_appgw_mappings)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;
  SshIpAddrStruct gwip;
  SshUInt32 flags;

  if (SSH_IP_IS6(&conn->context.responder_ip))
    gwip = conn->appgw_instance->gwip6;
  else
    gwip = conn->appgw_instance->gwip;

  flags = 0;
  if (conn->appgw_instance->flags & SSH_APPGW_F_NAT_KEEP_PORT)
    flags |= SSH_PME_APPGW_KEEP_INITIATOR_PORT;
  if (conn->appgw_instance->flags & SSH_APPGW_F_NAT_SHARE_PORT)
    flags |= SSH_PME_APPGW_ACCEPT_SHARED_PORT;

  SSH_ASSERT(conn->trigger_rule_index != SSH_IPSEC_INVALID_INDEX);

  /** Create application gateway mappings. */
  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Creating application gateway mappings: %@.%u > %@.%u (%@.%u)",
             ssh_ipaddr_render, &conn->context.initiator_ip,
             conn->context.initiator_port,
             ssh_ipaddr_render, &conn->context.responder_ip,
             conn->context.responder_port,
             ssh_ipaddr_render, &conn->context.responder_orig_ip,
             conn->context.responder_orig_port));
  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_mappings_done);
  SSH_FSM_ASYNC_CALL(
        ssh_pme_create_appgw_mappings(pm->engine,
                                      conn->u.init.current_rule_index,
                                      conn->initiator_flow_index,
                                      flags,
                                      conn->u.init.from_tunnel_id,
                                      conn->u.init.protocol,
                                      conn->ipproto,
                                      &conn->context.initiator_ip,
                                      conn->context.initiator_port,
                                      &conn->context.responder_orig_ip,
                                      conn->context.responder_orig_port,
                                      &conn->context.responder_ip,
                                      conn->context.responder_port,
                                      &gwip,
                                      conn->appgw_instance->gwport,
                                      (SshUInt16)
                                      (conn->appgw_instance->gwport + 1),
                                      conn->trigger_rule_index,
                                      conn->u.init.transform_index,
                                      conn->u.init.prev_transform_index,
                                      conn->u.init.flow_idle_timeout,
                                      ssh_pm_appgw_mappings_cb,
                                      thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_appgw_mappings_done)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;

  if (!SSH_IP_DEFINED(&conn->gw_ip))
    {
      /** Failed. */
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not create application gateway mappings"));
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_init_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Check what kind of NATs happen on initiator and responder sides. */
  if (!SSH_IP_EQUAL(&conn->context.initiator_ip,
                    &conn->context.initiator_ip_after_nat)
      || (conn->context.initiator_port
          != conn->context.initiator_port_after_nat))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("NAT on initiator side"));
      conn->initiator_nat = 1;
    }
  if (!SSH_IP_EQUAL(&conn->context.responder_orig_ip,
                    &conn->context.responder_ip_after_nat)
      || (conn->context.responder_orig_port
          != conn->context.responder_port_after_nat))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("NAT on responder side"));
      conn->responder_nat = 1;
    }

  /* Create object for communicating with the initiator and
     responder. */
  switch (conn->ipproto)
    {
    case SSH_IPPROTO_TCP:
      /** TCP. */
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_tcp);
      break;

    case SSH_IPPROTO_UDP:
      /** UDP. */
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_udp);
      break;

    default:
      /** Unsupported protocol. */
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_init_failed);
      break;
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_appgw_tcp)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;
  unsigned char addrbuf[SSH_IP_ADDR_STRING_SIZE];
  unsigned char portbuf[8];
  unsigned char gwaddrbuf[SSH_IP_ADDR_STRING_SIZE];
  unsigned char gwportbuf[8];
  SshTcpConnectParamsStruct params;

  /* Open stream to the responder. */

  ssh_ipaddr_print(&conn->gw_ip, addrbuf, sizeof(addrbuf));
  ssh_snprintf(ssh_sstr(portbuf), sizeof(portbuf),
               "%d", (int) conn->gw_responder_port);

  if (SSH_IP_IS6(&conn->gw_ip))
    ssh_ipaddr_print(&conn->appgw_instance->gwip6,
                     gwaddrbuf, sizeof(gwaddrbuf));
  else
    ssh_ipaddr_print(&conn->appgw_instance->gwip,
                     gwaddrbuf, sizeof(gwaddrbuf));

  ssh_snprintf(ssh_sstr(gwportbuf), sizeof(gwportbuf), "%u",
               (unsigned int) conn->appgw_instance->gwport + 1);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Opening responder stream %s:%s > %s:%s",
                              gwaddrbuf, gwportbuf, addrbuf, portbuf));

  memset(&params, 0, sizeof(params));
  params.local_address = gwaddrbuf;
  params.local_port_or_service = gwportbuf;
  params.local_reusable = SSH_TCP_REUSABLE_ADDRESS;

  /** Open responder stream. */
  conn->flow_reject = 0;
  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_tcp_responder_stream_done);
  SSH_FSM_ASYNC_CALL(ssh_tcp_connect(addrbuf, portbuf, &params,
                                     ssh_pm_appgw_responder_tcp_connect_cb,
                                     thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_appgw_tcp_responder_stream_done)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;
#ifdef DEBUG_LIGHT
  SshIpAddrStruct gwip;
#endif /* DEBUG_LIGHT */

  if (conn->context.responder_stream == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_init_failed);

      SSH_DEBUG(SSH_D_MIDOK,
                ("appgw initialization failed: flow_reject=%u",
                 conn->flow_reject));

      if (conn->flow_reject)
        {
          conn->flow_reject = 0;
          SSH_FSM_ASYNC_CALL(
                    ssh_pme_flow_set_status(conn->pm->engine,
                                            conn->initiator_flow_index,
                                            SSH_PME_FLOW_REJECT_INBOUND,
                                            ssh_pm_appgw_i_flow_enabled,
                                            thread));
          SSH_NOTREACHED;
        }

      return SSH_FSM_CONTINUE;
    }

  /* After we call ssh_pme_flow_set_status(..,TRUE,..)
     we must consider the Initiator stream to be Open */
  conn->state = SSH_PM_APPGW_I_STREAM_OPEN;
  conn->next = conn->appgw_instance->pending_connections;
  conn->appgw_instance->pending_connections = conn;

#ifdef DEBUG_LIGHT
  if (SSH_IP_IS6(&conn->gw_ip))
    gwip = conn->appgw_instance->gwip6;
  else
    gwip = conn->appgw_instance->gwip;
  SSH_DEBUG(SSH_D_HIGHSTART, ("Opening initiator stream %@:%d > %@:%d",
                              ssh_ipaddr_render, &conn->gw_ip,
                              conn->gw_initiator_port,
                              ssh_ipaddr_render, &gwip,
                              conn->appgw_instance->gwport));
#endif /* DEBUG_LIGHT */

  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_tcp_open_initiator_stream);
  SSH_FSM_ASYNC_CALL(ssh_pme_flow_set_status(conn->pm->engine,
                                             conn->initiator_flow_index,
                                             SSH_PME_FLOW_PASS,
                                             ssh_pm_appgw_i_flow_enabled,
                                             thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_appgw_tcp_open_initiator_stream)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;

  /* Cancel possible process packet timeout. */
  ssh_cancel_timeouts(ssh_pm_appgw_process_packet_timeout, conn);

  if (conn->context.initiator_stream)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Initiator stream opened"));

      /* We have successfully created the mappings and streams. */
      conn->state = SSH_PM_APPGW_CONNECTED;
      ssh_adt_detach_object(conn->pm->appgw_pending_conn_requests, conn);
      ssh_free(conn->u.init.packet);
      conn->u.init.packet = NULL;

      /* Notify main thread that this pending connection request is
         complete. */
      if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
        SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);

      conn->context.audit_event_generated = 0;

      /* Complete this application gateway request. */
      (*conn->appgw_instance->conn_callback)(
                                        &conn->context,
                                        SSH_APPGW_NEW_INSTANCE,
                                        NULL, 0,
                                        conn->appgw_instance->conn_context);

      if (conn->context.audit_event_generated == 0)
        ssh_appgw_audit_event(&conn->context,
                              SSH_AUDIT_APPGW_SESSION_START,
                              SSH_AUDIT_ARGUMENT_END);

      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_connected);
      return SSH_FSM_CONTINUE;
    }

  /* Is the retry limit reached? */
  if (conn->state == SSH_PM_APPGW_I_STREAM_OPEN_FAILED)
    {
      SshPmAppgwConn *connp;

    failed:
      SSH_DEBUG(SSH_D_FAIL, ("Could not open initiator stream"));

      /* Remove us from the list of pending connections. */
      for (connp = &conn->appgw_instance->pending_connections;
           *connp;
           connp = &((*connp)->next))
        if (*connp == conn)
          {
            /* Found us. */
            *connp = (*connp)->next;
            break;
          }

      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_init_failed);
      return SSH_FSM_CONTINUE;
    }

  /* And order a timeout for the process packet operation. */
  if (ssh_register_timeout(NULL,
                           0, 600000,
                           ssh_pm_appgw_process_packet_timeout, conn) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No space for appgw connection retry"));
      goto failed;
    }

  /* Iterate through SSH_PM_APPGW_I_STREAM_OPEN_RETRY{1..3} states */
  conn->state++;
  ssh_pme_process_packet(conn->pm->engine,
                         conn->u.init.from_tunnel_id,
                         conn->u.init.protocol,
                         conn->u.init.ifnum,
                         conn->u.init.flags | SSH_PME_PACKET_NOTRIGGER,
                         conn->u.init.prev_transform_index,
                         conn->u.init.packet, conn->u.init.packet_len);

  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(ssh_pm_st_appgw_udp)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;
  unsigned char addrbuf[SSH_IP_ADDR_STRING_SIZE];
  unsigned char portbuf[8];
  unsigned char gwaddrbuf[SSH_IP_ADDR_STRING_SIZE];
  unsigned char gwportbuf[8];

  /* Create UDP listeners. */

  /* Gateway addresses. */
  if (SSH_IP_IS6(&conn->gw_ip))
    ssh_ipaddr_print(&conn->appgw_instance->gwip6,
                     gwaddrbuf, sizeof(gwaddrbuf));
  else
    ssh_ipaddr_print(&conn->appgw_instance->gwip,
                     gwaddrbuf, sizeof(gwaddrbuf));
  ssh_ipaddr_print(&conn->gw_ip, addrbuf, sizeof(addrbuf));

  /* Responder port. */

  ssh_snprintf(ssh_sstr(gwportbuf), sizeof(gwportbuf), "%u",
               (unsigned int) conn->appgw_instance->gwport + 1);
  ssh_snprintf(ssh_sstr(portbuf), sizeof(portbuf), "%u",
               (unsigned int) conn->gw_responder_port);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Creating responder listener %s:%s > %s:%s",
                              gwaddrbuf, gwportbuf, addrbuf, portbuf));
  conn->context.responder_listener
    = ssh_udp_make_listener(gwaddrbuf, gwportbuf, addrbuf, portbuf, NULL,
                            ssh_pm_appgw_udp_r_callback, conn);
  if (conn->context.responder_listener == NULL)
    {
      /** Responder listener failed. */
      SSH_DEBUG(SSH_D_FAIL, ("Responder listener creation failed"));
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_init_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Initiator port. */

  ssh_snprintf(ssh_sstr(gwportbuf), sizeof(gwportbuf), "%u",
               (unsigned int) conn->appgw_instance->gwport);
  ssh_snprintf(ssh_sstr(portbuf), sizeof(portbuf), "%u",
               (unsigned int) conn->gw_initiator_port);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Creating initiator listener %s:%s > %s:%s",
                              gwaddrbuf, gwportbuf, addrbuf, portbuf));
  conn->context.initiator_listener
    = ssh_udp_make_listener(gwaddrbuf, gwportbuf, addrbuf, portbuf, NULL,
                            ssh_pm_appgw_udp_i_callback, conn);
  if (conn->context.initiator_listener == NULL)
    {
      /** Initiator listener failed. */
      SSH_DEBUG(SSH_D_FAIL, ("Initiator listener creation failed"));
      ssh_udp_destroy_listener(conn->context.responder_listener);
      conn->context.responder_listener = NULL;
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_init_failed);
      return SSH_FSM_CONTINUE;
    }

  /* We have successfully created the listeners. */
  conn->state = SSH_PM_APPGW_CONNECTED;
  ssh_adt_detach_object(conn->pm->appgw_pending_conn_requests, conn);

  /* Notify main thread that this pending connection request is
     complete. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);

  /* Complete this application gateway request. */
  (*conn->appgw_instance->conn_callback)(&conn->context,
                                         SSH_APPGW_NEW_INSTANCE,
                                         NULL, 0,
                                         conn->appgw_instance->conn_context);

  /** Switch flow to pass state. */
  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_udp_process_packet);
  SSH_FSM_ASYNC_CALL(ssh_pme_flow_set_status(conn->pm->engine,
                                             conn->initiator_flow_index,
                                             SSH_PME_FLOW_PASS,
                                             ssh_pm_appgw_i_flow_enabled,
                                             thread));
  /* NOTREACHED */
}

SSH_FSM_STEP(ssh_pm_st_appgw_udp_process_packet)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;

  /* And reprocess initiator's first packet. */
  ssh_pme_process_packet(pm->engine,
                         conn->u.init.from_tunnel_id,
                         conn->u.init.protocol,
                         conn->u.init.ifnum,
                         conn->u.init.flags | SSH_PME_PACKET_NOTRIGGER,
                         conn->u.init.prev_transform_index,
                         conn->u.init.packet, conn->u.init.packet_len);

  /* We do not need the packet anymore. */
  ssh_free(conn->u.init.packet);
  conn->u.init.packet = NULL;

  /** Connected. */
  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_connected);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_appgw_init_failed)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;

  pm->stats.appgw_conn_failed++;

  ssh_adt_detach_object(conn->pm->appgw_pending_conn_requests, conn);
  ssh_free(conn->u.init.packet);

  /* Notify main thread that this pending connection request is
     complete. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);

  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_appgw_connected)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;

  /* Clear the aborted status. */
  conn->aborted = 0;
  conn->is_waiting_for_continue = 0;

  /* Act upon signal flags */
  if (conn->flow_invalid)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("sending SSH_APPGW_FLOW_INVALID event to appgw instance "
                 "for session %@:%u -> %@:%u",
                 ssh_ipaddr_render,
                 &conn->context.initiator_ip,
                 conn->context.initiator_port,
                 ssh_ipaddr_render,
                 &conn->context.responder_orig_ip,
                 conn->context.responder_orig_port));

      conn->flow_invalid = 0;

      (*conn->appgw_instance->conn_callback)(
                                      &conn->context,
                                      SSH_APPGW_FLOW_INVALID,
                                      NULL, 0,
                                      conn->appgw_instance->conn_context);
    }


  /* Execute state related actions */
  switch (conn->state)
    {
    case SSH_PM_APPGW_CONNECTED:
      conn->is_waiting_for_continue = 1;
      return SSH_FSM_SUSPENDED;
      break;

    case SSH_PM_APPGW_OPEN_PORT:
      /* Init results. */
      conn->u.open_port.freeing_index = SSH_IPSEC_INVALID_INDEX;
      conn->u.open_port.rule_index = SSH_IPSEC_INVALID_INDEX;

      /* Process the open port request. */
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_open_port);
      break;

    case SSH_PM_APPGW_DONE:
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_terminate);
      break;

    default:
      ssh_fatal("Application gateway thread reached invalid state %d at "
                "ssh_pm_st_appgw_connected", conn->state);
      break;
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_appgw_open_port)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;
  Boolean need_nat_port = FALSE;

  /* Check if the operation is aborted. */
  if (conn->aborted)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_open_port_abort);
      return SSH_FSM_CONTINUE;
    }

  /* Is there NAT at the responder direction? */
  if (conn->u.open_port.flags & SSH_APPGW_OPEN_FROM_INITIATOR)
    {
      /* Data session opening comes from initiator, check if responder
         is behind dynamic NAT (unlikely scenario). */
      if (conn->responder_nat && !SSH_IP_DEFINED(&conn->rule->nat_dst_low))
        need_nat_port = TRUE;
    }
  else
    {
      /* The session opening comes from the responder, check if
         initiator is behind dynamic NAT. */
      if (conn->initiator_nat && !SSH_IP_DEFINED(&conn->rule->nat_src_low))
        need_nat_port = TRUE;
    }

  /* Do we need to NAT the selector? */
  if (need_nat_port)
    conn->u.open_port.port_dst_port = 0;
  else
    conn->u.open_port.port_dst_port = conn->u.open_port.dst_port;

  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_open_port_create_rule);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_appgw_open_port_create_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshPmTunnel tunnel;

  if (conn->failed == 1)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_open_port_create_rule_result);
      return SSH_FSM_CONTINUE;
    }

  /* Check whether we need an instance of a tunnel */
  if (conn->u.open_port.flags & SSH_APPGW_OPEN_FROM_INITIATOR)
    tunnel = conn->rule->side_to.tunnel;
  else
    tunnel = conn->rule->side_from.tunnel;

  /* In this state we generate the master open port rule, this is
     either a TRIGGER rule without a transform_index or a PASS rule. */
  ssh_pm_appgw_make_dynamic_port_rule(conn, &engine_rule);

  /* This rule must exist in the engine untill close_port() is called. */
  engine_rule.flags |= SSH_ENGINE_RULE_PM_REFERENCE;

  if (tunnel != NULL)
    {
      engine_rule.type = SSH_ENGINE_RULE_TRIGGER;
      engine_rule.policy_context = conn;

      if (conn->u.open_port.flags & SSH_APPGW_OPEN_THISGW)
        engine_rule.flags |= SSH_PM_ENGINE_RULE_APPGW;

      engine_rule.flags |= SSH_ENGINE_RULE_UNDEFINED;
    }
  else
    {
      if (conn->u.open_port.flags & SSH_APPGW_OPEN_THISGW)
        {
          engine_rule.type = SSH_ENGINE_RULE_TRIGGER;
          engine_rule.policy_context = conn;
          engine_rule.flags |= SSH_PM_ENGINE_RULE_APPGW;
        }
    }

  /* Mark that the rule index value can be overwritten by the callback */
  conn->u.open_port.rule_index = SSH_IPSEC_INVALID_INDEX;
  conn->u.open_port.port_dst_alloc = 0;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Creating engine rule #1"));
  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_open_port_create_rule_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_appgw_add_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_appgw_open_port_create_rule_result)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;

  /* Uncache the NAT port allocated by the engine */
  if (conn->u.open_port.port_dst_alloc)
    conn->u.open_port.port_dst_port = conn->u.open_port.port_dst_alloc;

  /* Both rules were not correctly instantiated, remove the master
     one and mark it as unmade. */
  if (conn->failed && conn->u.open_port.rule_index != SSH_IPSEC_INVALID_INDEX)
    {
      ssh_pme_delete_rule(conn->pm->engine, conn->u.open_port.rule_index,
                          NULL_FNPTR, NULL);
      conn->u.open_port.rule_index = SSH_IPSEC_INVALID_INDEX;
    }

  /* Check if the operation is aborted. */
  if (conn->aborted)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_open_port_abort);
      return SSH_FSM_CONTINUE;
    }

  if (conn->u.open_port.rule_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Engine rule creation failed"));
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_open_port_failed);
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Rule created"));
      SSH_FSM_SET_NEXT(ssh_pm_st_appgw_open_port_finish);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_appgw_open_port_failed)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;

  /* Rule index marks the success of the operation. */
  conn->u.open_port.rule_index = SSH_IPSEC_INVALID_INDEX;

  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_open_port_finish);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_appgw_open_port_finish)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;

  /* Notify user. */
  if (conn->u.open_port.rule_index == SSH_IPSEC_INVALID_INDEX)
    /* Operation failed. */
    (*conn->u.open_port.callback)(&conn->context, FALSE, NULL, 0, 0,
                                  conn->u.open_port.context);
  else
    /* Operation was successful. */
    (*conn->u.open_port.callback)(&conn->context, TRUE,
                                  &conn->u.open_port.port_dst_ip,
                                  conn->u.open_port.port_dst_port,
                                  conn->u.open_port.rule_index,
                                  conn->u.open_port.context);

  /* Unregister operation handle. */
  ssh_operation_unregister(conn->u.open_port.handle);

  /* The `open port' operation complete.  Let's go back to wait for
     new operations. */
  conn->state = SSH_PM_APPGW_CONNECTED;

  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_connected);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_appgw_open_port_abort)
{
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;

  SSH_ASSERT(conn->aborted);
  conn->aborted = 0;

  /* Free allocated resources. */
  if (conn->u.open_port.rule_index != SSH_IPSEC_INVALID_INDEX)
    ssh_pme_delete_rule(conn->pm->engine, conn->u.open_port.rule_index,
                        NULL_FNPTR, NULL);

  SSH_FSM_SET_NEXT(ssh_pm_st_appgw_connected);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_appgw_terminate)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmAppgwConn conn = (SshPmAppgwConn) thread_context;
  SshPmAppgwConn *iter;
  size_t ki,kr;

  SSH_DEBUG(SSH_D_HIGHSTART,("terminating appgw instance"));

  /* Relase allocated resources. */

  if (conn->context.responder_stream)
    ssh_stream_destroy(conn->context.responder_stream);
  if (conn->context.initiator_stream)
    ssh_stream_destroy(conn->context.initiator_stream);

  if (conn->context.initiator_listener)
    ssh_udp_destroy_listener(conn->context.initiator_listener);
  if (conn->context.responder_listener)
    ssh_udp_destroy_listener(conn->context.responder_listener);

  /* Remove us from the flow_id->map table */
  ki = conn->initiator_flow_index % SSH_APPGW_FLOW_HASH_SIZE;
  kr = conn->responder_flow_index % SSH_APPGW_FLOW_HASH_SIZE;

  iter = &pm->flow_map_i[ki];
  while (*iter)
    {
      if (*iter == conn)
        {
          *iter = (*iter)->flow_map_i_next;
          break;
        }
      iter = &((*iter)->flow_map_i_next);
    }

  iter = &pm->flow_map_r[kr];
  while (*iter)
    {
      if (*iter == conn)
        {
          *iter = (*iter)->flow_map_r_next;
          break;
        }
      iter = &((*iter)->flow_map_r_next);
    }

  /* We just closed some TCP/UDP streams.  Let's give 1 second time
     for the possible TCP sessions to close nicely. */
  pm->earliest_shutdown = ssh_time() + 2;










  return SSH_FSM_FINISH;
}

#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
