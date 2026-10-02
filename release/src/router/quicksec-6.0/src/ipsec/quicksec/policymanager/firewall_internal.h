/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for the Quicksec Firewall Policy Manager.
*/

#ifndef FIREWALL_INTERNAL_H
#define FIREWALL_INTERNAL_H

#include "sshincludes.h"
#ifdef SSHDIST_IPSEC_FIREWALL
#include "appgw_api.h"

/** States for an application gateway connection. */
typedef enum
{
  SSH_PM_APPGW_START,
  SSH_PM_APPGW_REDIRECT,
  SSH_PM_APPGW_I_STREAM_OPEN,
  SSH_PM_APPGW_I_STREAM_OPEN_RETRY1,
  SSH_PM_APPGW_I_STREAM_OPEN_RETRY2,
  SSH_PM_APPGW_I_STREAM_OPEN_RETRY3,
  SSH_PM_APPGW_I_STREAM_OPEN_FAILED,
  SSH_PM_APPGW_CONNECTED,
  SSH_PM_APPGW_OPEN_PORT,
  SSH_PM_APPGW_DONE
} SshPmAppgwConnState;


/** An application gateway connection. */
struct SshPmAppgwConnRec
{
  /** Inlined ADT header.  All pending application gateway requests are
     hold in an ADT bag until the connection is successfully
     established or until the connection establishment fails.  This is
     needed to detect retransmitted packets of the same flow before we
     have installed engine flows to handle the traffic of the
     application gateway connection. */
  SshADTBagHeaderStruct adt_header;

  /** An FSM thread handling this connection. */
  SshFSMThreadStruct thread;

  /** Link field when we are waiting at `registration' for the
     initiator stream. */
  struct SshPmAppgwConnRec *next;

  /** Back-pointer to policy manager. */
  SshPm pm;

  /** Context data for an application gateway instance. */
  SshAppgwContextStruct context;

  /* Flags. */
  unsigned int initiator_nat : 1; /** NAT on initiator side. */
  unsigned int responder_nat : 1; /** NAT on responder side. */
  unsigned int aborted : 1;       /** Asynchronous operation aborted. */
  unsigned int flow_invalid : 1;  /** A flow has been invalidated. */
  unsigned int flow_reject : 1;   /** Set flow to reject mode. */
  unsigned int is_waiting_for_continue : 1; /** The appgw thread must be
                                               woken up for any processing
                                               to occur. */
  unsigned int is_dummy : 1;      /** Is a dummy connection for the audit
                                     framework. */
  unsigned int should_audit : 1;  /** Should events from this appgw connection
                                     be audited. */
  unsigned int failed : 1;        /** Failure detected */
  unsigned int is_waiting_for_qm : 1; /** Appgw thread is waiting for
                                         quick mode thread. */

  /** IP protocol of this connection. */
  SshUInt8 ipproto;

  /** Connection point to the gateway. */
  SshIpAddrStruct gw_ip;

  /** Ports at the gateway. */
  SshUInt16 gw_initiator_port;
  SshUInt16 gw_responder_port;

  /** The high-level policy rule that was used for this connection.
     The application gateway connections do not take reference to the
     rule below.  Since the appgw connections are flows depending on
     the rule (and the dynamic ports depend on the same rule too), all
     connections will disappear when the policy rule is removed and
     there is no need to lock the rule. */
  SshPmRule rule;

  /** Initiator flow. */
  SshUInt32 initiator_flow_index;

  /** Responder flow. */
  SshUInt32 responder_flow_index;

  /** Index of the trigger rule that created this connection. */
  SshUInt32 trigger_rule_index;

  /** Application gateway. */
  struct SshPmAppgwRec *appgw;

  /** Application gateway instance. */
  struct SshPmAppgwInstanceRec *appgw_instance;

  /** The state of the connection. */
  SshPmAppgwConnState state;

  /** Pointers for connections on the flow_map tables */
  struct SshPmAppgwConnRec *flow_map_i_next;
  struct SshPmAppgwConnRec *flow_map_r_next;

  /** State dependent arguments. */
  union
  {
    /** Opening new application gateway connection. */
    struct
    {
      SshInterceptorProtocol protocol;
      SshUInt32 ifnum;
      SshUInt32 flags;
      SshUInt32 from_tunnel_id;
      SshUInt32 to_tunnel_id;
      SshUInt32 transform_index;
      SshUInt32 prev_transform_index;
      SshUInt32 flow_idle_timeout;
      SshUInt32 current_rule_index;
      unsigned char *packet;
      size_t packet_len;
    } init;

    /** Opening an auxiliary port. */
    struct
    {
      /** Arguments. */
      SshUInt8 ipproto;
      SshUInt16 forced_dst_port;
      SshUInt16 src_port;
      SshUInt16 dst_port;
      SshUInt32 flags;

      SshAppgwOpenCB callback;
      void *context;
      SshUInt32 flow_idle_timeout;

      /** Operation handle. */
      SshOperationHandle handle;

      /** Results. */
      SshUInt32 freeing_index;
      SshIpAddrStruct port_dst_ip;
      SshUInt16 port_dst_alloc;
      SshUInt16 port_dst_port;
      SshUInt32 rule_index;
    } open_port;
  } u;
};

typedef struct SshPmAppgwConnRec SshPmAppgwConnStruct;
typedef struct SshPmAppgwConnRec *SshPmAppgwConn;

/** A registered application gateway instance. */
struct SshPmAppgwInstanceRec
{
  /** List of pending initiator stream openings. */
  SshPmAppgwConn pending_connections;

  /* Flags. */
  unsigned int valid : 1;       /** Instance is valid. */
  unsigned int local : 1;       /** Local application gateway. */
  unsigned int shutdown : 1;    /** Shutdown notified for this instance. */

  /** The load of the application gateway. */
  SshUInt32 load;

  /** The unique IDs of the service objects using this instance.
      Unused slots have the value 0 which is an invalid service ID. */
  SshUInt32 service_ids[SSH_PM_MAX_SERVICES];








  /** Number of application gateway connections referencing this
      gateway. */
  SshUInt32 num_connections;

  /** IP Address of the host running the application gateway. */
  SshIpAddrStruct gwip;
  SshIpAddrStruct gwip6;

  /** Port number for the application gateway on the appgw host. */
  SshUInt16 gwport;

  /** Appgw flags. */
  SshUInt32 flags;

  /** Default flow idle timeout for flows for this appgw */
  SshUInt32 flow_idle_timeout;

  /** New connection callback. */
  SshAppgwConnCB conn_callback;
  void *conn_context;

  /** Type (local, remote) specific context. */
  union
  {
    struct
    {
      SshUInt32      ifnum;
      SshTcpListener tcp_listener;
      SshTcpListener tcp_listener6;
    } local;
  } u;
};

typedef struct SshPmAppgwInstanceRec SshPmAppgwInstanceStruct;
typedef struct SshPmAppgwInstanceRec *SshPmAppgwInstance;

/** An application gateway. */
struct SshPmAppgwRec
{
  /** A link field for application gateways. */
  struct SshPmAppgwRec *next;

  /** Identifier for the application gw. */
  char ident[SSH_APPGW_MAX_IDENT_LEN];

  /** Connection callback, stored for interface
      changes. */
  SshAppgwConnCB conn_callback;

  /** Connection context for the connection callback. */
  void *conn_context;

  /** Connection parameters for the application gateway */
  SshAppgwParamsStruct appgw_conn_params;

  /** Stored connection flags. */
  SshUInt32 conn_flags;

  /** Version number of the application gateway. */
  SshUInt32 version;

  /** The protocol for which this gateway applies to. */
  SshUInt8 ipproto;




  SshUInt8 locals_destroyed;

  /** Hosts serving this application gateway.  Unused slots do not have
     `valid' field set. */
  SshPmAppgwInstanceStruct hosts[SSH_PM_MAX_APPGW_HOSTS];
};

typedef struct SshPmAppgwRec SshPmAppgwStruct;
typedef struct SshPmAppgwRec *SshPmAppgw;

/* ************************** Application gateways ***************************/

/** Initialize application gateway module for the policy manager
   `pm'. */
Boolean ssh_pm_appgw_init(SshPm pm);

/** Uninitialize the application gateway module from the policy manager
   `pm'.  The application gateway instances must be shut down before
   this is called. */
void ssh_pm_appgw_uninit(SshPm pm);

/** Notify application gateway module about updated interface
   information. */
void ssh_pm_appgw_interface_change(SshPm pm);

/** Notify application gateway about a new packet for the service
   `service'.  The argument `rule' is the high-level policy rule that
   specified this application gateway processing.  The argument
   `master_connection' specifies the application gateway connection
   that opened this connection through itself.  It has the value NULL
   if this is a master connection.  The arguments `packet_src',
   `packet_dst', `packet_ipproto', `packet_src_port' and
   `packet_dst_port' are selectors, extacted from the IP header of the
   triggered packet.

   The arguments `packet_nat_dst' and `packet_nat_dst_port' specify
   the address to which the packet would be NATted if the application
   gateway trigger rule would have been a passby rule.  These are
   specified only for dynamically opened application ports which go
   through the master application gateway (SSH_APPGW_OPEN_THISGW).
   They are unset for other application gateway triggers.

   The arguments `packet', `packet_len' specify the triggered packet.
   The function must free the data, pointed by `packet' after it is
   not needed anymore.  The service specification `service' and the
   packet selectors remain valid as long as the control is in the
   function.  If the function needs these values, it must take a copy
   of them. */
void ssh_pm_appgw_request(SshPm pm, SshPmRule rule,
                          SshPmService service,
                          SshPmAppgwConn master_connection,
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
                          SshIpAddr packet_nat_dst,
                          SshUInt16 packet_nat_dst_port,
                          unsigned char *packet, size_t packet_len);

/** Notification to the appgw framework, that a quickmode negotiation
   'conn' was completed and resulted in 'trd_idx' transform present
   in the engine. If 'trd_idx' is SSH_IPSEC_INVALID_INDEX, then it
   is assumed that the negotiation failed. */
void
ssh_pm_st_appgw_open_port_qm_cb(SshPm pm, SshPmAppgwConn conn,
                                SshUInt32 trd_idx);

/** Create an appgw to-tunnel rule instantiating TRIGGER or APPLY
   rule in the engine. The triggering rule must be provided
   as 'basis' and the transform index in the forward direction
   as 'trd_index'. 'is_new_session' must be set, if this is
   a new fresh session, and not a rule for recovering a dangling
   flow. */
void
ssh_appgw_create_totunnel_rule(SshPm pm,
                               const SshEnginePolicyRule basis,
                               SshUInt32 trd_index,
                               Boolean is_new_session,
                               SshPmeAddRuleCB callback,
                               void *context);

/** Notification of a flow invalidation in the engine to the
   appgw framework. */
void
ssh_pm_appgw_flow_free_notification(SshPm pm,
                                    SshUInt32 flow_index);

/** Find and remove from the flow index -> SshPmAppgwConn
   mappings a flow which has the specified flow index.
   If such a SshPmAppgwConn object is found, then it is returned. */
SshPmAppgwConn
ssh_pm_appgw_find_conn_and_remove(SshPm pm,
                                  SshUInt32 flow_index);

/** Allocate a new application gateway structure. */
SshPmAppgw ssh_pm_appgw_alloc(SshPm pm);

/** Free application gateway structure `appgw' and put it back to the
   policy manager's freelist. */
void ssh_pm_appgw_free(SshPm pm, SshPmAppgw appgw);

/** Allocate a new application gateway connection structure. */
SshPmAppgwConn ssh_pm_appgw_connection_alloc(SshPm pm);

/** Free application gateway connection structure `conn' and put it
   back to the policy manager's freelist. */
void ssh_pm_appgw_connection_free(SshPm pm, SshPmAppgwConn conn);

#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* not FIREWALL_INTERNAL_H */
