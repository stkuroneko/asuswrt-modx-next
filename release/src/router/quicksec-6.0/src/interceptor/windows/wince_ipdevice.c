/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Platform dependent IP protocol stack information retrieval and
   configuration interface for Windows CE.
*/

#ifdef _WIN32_WCE

#include "sshincludes.h"
#include "interceptor_i.h"
#include "ipdevice.h"
#include "ipdevice_internal.h"
#include "kernel_timeouts.h"
#include <iphlpapi.h>
#if defined (WITH_IPV6)
#ifndef UNDER_CE
#define UNDER_CE
#endif /* UNDER_CE */
#include <ntddip6.h>
#endif /* WITH_IPV6 */

#if defined (WITH_IPV6)

typedef struct SshIpv6UpdateAddressRec
{
  IPV6_UPDATE_ADDRESS request;

  /* Extra data members for asynchronous completion */
  SshIPDeviceCompletionCB callback;
  void *context;
} SshIpv6UpdateAddressStruct, *SshIpv6UpdateAddress;

#endif /* WITH_IPV6 */

/*--------------------------------------------------------------------------
  Local functions.
  --------------------------------------------------------------------------*/

static Boolean
ssh_ipdev_ip4_query_interfaces(SshIPDevice device,
                               SshIpdevInterfaceList if_list);

static Boolean
ssh_ipdev_ip4_query_addresses(SshIPDevice device,
                              SshIpdevAddressList addr_list);

static Boolean
ssh_ipdev_ip4_query_routes(SshIPDevice device,
                           SshIpdevRouteList route_list);

static Boolean
ssh_ipdev_ip4_find_first_address(SshIPDevice device,
                                 SshIFIndex system_idx,
                                 SshAddressCtx *ctx_return);
static Boolean
ssh_ipdev_configure_i(SshIPDevice device, 
                      SshIFIndex system_idx,
                      SshUInt16 configure_type, 
                      void *configure_params);

static void
ssh_ipdev_ip4_clear_address(SshIPDevice device,
                            SshAddressCtx addr_ctx,
                            SshIPDeviceCompletionCB callback,
                            void *context);

static void
ssh_ipdev_ip4_set_address(SshIPDevice device,
                          SshAddressCtx addr_ctx,
                          SshIpAddr ip,
                          SshIPDeviceCompletionCB callback,
                          void *context);

static void
ssh_ipdev_ip4_add_address(SshIPDevice device,
                          SshIFIndex system_idx,
                          SshInterceptorIfnum ifnum,
                          SshIpAddr ip,
                          SshAddressCtx *ctx_return,
                          SshIPDeviceCompletionCB callback,
                          void *context);

static void
ssh_ipdev_ip4_delete_address(SshIPDevice device,
                             SshAddressCtx addr_ctx,
                             SshIPDeviceCompletionCB callback,
                             void *context);

#if defined (WITH_IPV6)
static Boolean
ssh_ipdev_ip6_query_interfaces(SshIPDevice device,
                               SshIpdevInterfaceList if_list);

static Boolean
ssh_ipdev_ip6_query_addresses(SshIPDevice device,
                              SshIpdevAddressList addr_list);

static Boolean
ssh_ipdev_ip6_query_routes(SshIPDevice device,
                           SshIpdevRouteList route_list);

static void
ssh_ipdev_ip6_add_address(SshIPDevice device,
                          SshIFIndex system_idx,
                          SshInterceptorIfnum ifnum,
                          SshIpAddr ip,
                          SshAddressCtx *ctx_return,
                          SshIPDeviceCompletionCB callback,
                          void *context);

static void
ssh_ipdev_ip6_delete_address(SshIPDevice device,
                             SshAddressCtx addr_ctx,
                             SshIPDeviceCompletionCB callback,
                             void *context);

static void
ssh_ipdev_ip6_add_route(SshIPDevice device,
                        SshIPRoute route,
                        SshIPDeviceCompletionCB callback,
                        void *context);

static void
ssh_ipdev_ip6_remove_route(SshIPDevice device,
                           SshIPRoute route,
                           SshIPDeviceCompletionCB callback,
                           void *context);

#endif /* WITH_IPV6 */

/*--------------------------------------------------------------------------
  Windows CE platform dependent functions for 'SshIPDevice' object.
  --------------------------------------------------------------------------*/

Boolean
ssh_ipdev_platform_init(SshIPDevice device)
{
  if (device->dev_id == SSH_DD_ID_IP4) 
    {
      SSH_DEBUG(SSH_D_HIGHSTART, 
                ("Initializing IPv4 protocol stack interface..."));

      device->query_interface_list = ssh_ipdev_ip4_query_interfaces;
      device->query_address_list = ssh_ipdev_ip4_query_addresses;
      device->query_route_list = ssh_ipdev_ip4_query_routes;
      device->find_first_address = ssh_ipdev_ip4_find_first_address;
      device->clear_address = ssh_ipdev_ip4_clear_address;
      device->set_address = ssh_ipdev_ip4_set_address;
      device->add_address = ssh_ipdev_ip4_add_address;
      device->delete_address = ssh_ipdev_ip4_delete_address;
      device->add_route = NULL;
      device->remove_route = NULL;
      device->configure = ssh_ipdev_configure_i;
    }
#if defined (WITH_IPV6)
  else if (device->dev_id == SSH_DD_ID_IP6)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, 
                ("Initializing IPv6 protocol stack interface..."));

      device->query_interface_list = ssh_ipdev_ip6_query_interfaces;
      device->query_address_list = ssh_ipdev_ip6_query_addresses;
      device->query_route_list = ssh_ipdev_ip6_query_routes;
      device->add_address = ssh_ipdev_ip6_add_address;
      device->delete_address = ssh_ipdev_ip6_delete_address;
      device->add_route = ssh_ipdev_ip6_add_route;
      device->remove_route = ssh_ipdev_ip6_remove_route;
      device->configure = ssh_ipdev_configure_i;
    }
#else
  else
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Unsupported IP device (ID = %d)", device->dev_id));
      return FALSE;
    }
#endif /* WITH_IPV6 */

  return TRUE;
}


void
ssh_ipdev_platform_uninit(SshIPDevice device)
{
  /* Nothing to do */
}


Boolean 
ssh_ipdev_platform_connect(SshIPDevice device)
{
  if (device->dev_id == SSH_DD_ID_IP6)
    {
      device->context = CreateFile(DD_IPV6_DEVICE_NAME,
                                   GENERIC_READ | GENERIC_WRITE, 
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, 
                                   NULL, OPEN_ALWAYS, 0, NULL);
      if (device->context == INVALID_HANDLE_VALUE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to open IPv6 device"));
          return FALSE;
        }

      SSH_DEBUG(SSH_D_HIGHOK, ("Successfully opened IPv6 device."));
    }

  return TRUE;
}


void
ssh_ipdev_platform_disconnect(SshIPDevice device)
{
  if (device->dev_id == SSH_DD_ID_IP6)
    {
      if (device->context != INVALID_HANDLE_VALUE)
        CloseHandle(device->context);
    }
}


static void
ssh_ipdev_ip4_decode_interface(SshIpdevInterfaceInfo if_info,
                               MIB_IFROW *if_row)
{
  SSH_ASSERT(if_info != NULL);
  SSH_ASSERT(if_row != NULL);

  memset(if_info, 0x00, sizeof(*if_info));

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("- Name:"), 
                    (const unsigned char *)if_row->wszName, 
                    wcslen(if_row->wszName) * sizeof(if_row->wszName[0]));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("- Description:"), 
                    if_row->bDescr, if_row->dwDescrLen);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Index: %u", if_row->dwIndex));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", if_row->dwType));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- MTU: %u", if_row->dwMtu));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Speed: %u", if_row->dwSpeed));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- AdminStatus: %u", 
                               if_row->dwAdminStatus));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- OperStatus: %u", if_row->dwOperStatus));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("- Physical address:"),
                    if_row->bPhysAddr, if_row->dwPhysAddrLen);

  if (if_row->dwType == MIB_IF_TYPE_LOOPBACK)
    if_info->is_loopback = 1;

  /* Indexes */
  if_info->system_idx = if_row->dwIndex;

  /* Save interface description (and length), because this will be later
     needed in adapter object lookup (in case there are more than one 
     virtual adapters having the same media address). */
  SSH_ASSERT(if_row->dwDescrLen <= SSH_MAX_IF_DESCR_LEN);
  memcpy(if_info->id.u.d.description, if_row->bDescr, if_row->dwDescrLen);
  if_info->id.u.d.description_len = if_row->dwDescrLen;
  if_info->id.id_type = SSH_IF_ID_DESCRIPTION;

  /* Media address with workaround for dial-up interfaces. */
  if (if_row->dwType != MIB_IF_TYPE_PPP)
    {
      SSH_ASSERT(if_row->dwPhysAddrLen <= 0xFF);
      if_info->media_addr_len = (SshUInt16)if_row->dwPhysAddrLen;
      memcpy(if_info->media_address, 
             if_row->bPhysAddr, 
             if_info->media_addr_len);
    }
  else
    {
      if_info->media_addr_len = sizeof SSH_ADAPTER_PHYS_ADDRESS_WAN;
      memcpy(if_info->media_address, SSH_ADAPTER_PHYS_ADDRESS_WAN,
             if_info->media_addr_len);
    }
  if_info->has_media_address = 1;

  /* MTU */
  SSH_ASSERT(if_row->dwMtu != 0);
  if_info->mtu = if_row->dwMtu;
  if_info->has_mtu = 1;
}

static void
ssh_ipdev_ip4_decode_route(SshIpdevRouteInfo route,
                           MIB_IPFORWARDROW *ip4_ri)
{
  SSH_ASSERT(route != NULL);
  SSH_ASSERT(ip4_ri != NULL);

  memset(route, 0x00, sizeof(route));

  /* Set destination, mask and next hop address */
  SSH_IP4_DECODE(&route->dest, &ip4_ri->dwForwardDest);
  SSH_IP4_DECODE(&route->gw, &ip4_ri->dwForwardNextHop);
  SSH_IP4_DECODE(&route->nm, &ip4_ri->dwForwardMask);
  route->nm_len = ssh_ip_net_mask_calc_prefix_len(&route->nm);

  /* Indexes */
  route->system_idx = ip4_ri->dwForwardIfIndex;

  /* Route type */
  if (ip4_ri->dwForwardType == MIB_IPROUTE_TYPE_DIRECT)
    route->type = SSH_IP_ROUTE_DIRECT;
  else
    route->type = SSH_IP_ROUTE_INDIRECT;

  /* 1st metric */
  route->metric = ip4_ri->dwForwardMetric1;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Dest: %@", ssh_ipaddr_render, &route->dest));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Mask: %@", ssh_ipaddr_render, &route->nm));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- NextHop: %@", ssh_ipaddr_render, &route->gw));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- IfIndex: %u", ip4_ri->dwForwardIfIndex));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", ip4_ri->dwForwardType));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Policy: %u", ip4_ri->dwForwardPolicy));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Proto: %u", ip4_ri->dwForwardProto));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Age: %u", ip4_ri->dwForwardAge));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- NextHopAS: %u", ip4_ri->dwForwardNextHopAS));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Metric1: %u", ip4_ri->dwForwardMetric1));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Metric2: %u", ip4_ri->dwForwardMetric2));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Metric3: %u", ip4_ri->dwForwardMetric3));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Metric4: %u", ip4_ri->dwForwardMetric4));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Metric5: %u", ip4_ri->dwForwardMetric5));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("(- MTU: %u)", route->mtu));
}


static void
ssh_ipdev_ip4_decode_address(SshIpdevAddressInfo addr,
                             MIB_IPADDRROW *ip4_ai)
{
  SshUInt32 broadcast_addr;

  SSH_ASSERT(addr != NULL);
  SSH_ASSERT(ip4_ai != NULL);

  memset(addr, 0x00, sizeof(*addr));

  addr->if_addr.protocol = SSH_PROTOCOL_IP4;
  SSH_IP4_DECODE(&addr->if_addr.addr.ip.ip, &ip4_ai->dwAddr);
  SSH_IP4_DECODE(&addr->if_addr.addr.ip.mask, &ip4_ai->dwMask);

  /* Generate broadcast address */
  broadcast_addr = ip4_ai->dwAddr & ip4_ai->dwMask;
  if (ip4_ai->dwBCastAddr)
    broadcast_addr |= ~(ip4_ai->dwMask);
  SSH_IP4_DECODE(&addr->if_addr.addr.ip.broadcast, &broadcast_addr);

  addr->system_idx = ip4_ai->dwIndex;
  addr->address_id = ip4_ai->unused1;
  addr->type = ip4_ai->wType;
  addr->dad_state = DAD_STATE_PREFERRED;
  addr->valid_lifetime = (SshUInt32)-1;
  addr->preferred_lifetime = (SshUInt32)-1;
  addr->reasm_size = ip4_ai->dwReasmSize;
  addr->timestamp = 0; /* Not used */

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Address: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.ip));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Mask: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.mask));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Broadcast address: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.broadcast));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", addr->type));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Index: %u", addr->system_idx));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- ReasmSize: %u", addr->reasm_size));
}


#if defined (WITH_IPV6)
static void
ssh_ipdev_ip6_decode_interface(SshIpdevInterfaceInfo if_info,
                               IPV6_INFO_INTERFACE *ip6_ii)
{
  SSH_ASSERT(if_info != NULL);
  SSH_ASSERT(ip6_ii != NULL);

  memset(if_info, 0x00, sizeof(*if_info));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Index: %u", ip6_ii->This.Index));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- GUID: %@", ssh_guid_render, &ip6_ii->This.Guid));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", ip6_ii->Type));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- MediaStatus: %u", ip6_ii->MediaStatus));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- TrueLinkMTU: %u", ip6_ii->TrueLinkMTU));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- LinkMTU: %u", ip6_ii->LinkMTU));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- DADTransmits: %u", ip6_ii->DupAddrDetectTransmits));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- FirewallEnabled: %u", ip6_ii->FirewallEnabled));
#ifdef DEBUG_LIGHT
  if (ip6_ii->LocalLinkLayerAddress)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("- Physical address:"),
                        (char *)ip6_ii + ip6_ii->LocalLinkLayerAddress, 
                        ip6_ii->LinkLayerAddressLength);
    }
#endif

  /* Skip possible loopback interface */
  if (ip6_ii->Type == IPV6_IF_TYPE_LOOPBACK)
    if_info->is_loopback = 1;

  /* Indexes */
  if_info->system_idx = ip6_ii->This.Index;

  /* Save interface GUID, because this will be later needed in adapter
     object lookup (in case there are more than one virtual adapters
     having the same media address). */
  if_info->id.u.guid = ip6_ii->This.Guid;
  if_info->id.id_type = SSH_IF_ID_GUID;

  /* Physical address */
  if (ip6_ii->LinkLayerAddressLength == SSH_ETHERH_ADDRLEN &&
      ip6_ii->LocalLinkLayerAddress != 0)
    {
      memcpy(if_info->media_address,
             (char *)ip6_ii + ip6_ii->LocalLinkLayerAddress,
             SSH_ETHERH_ADDRLEN);

      if_info->media_addr_len = SSH_ETHERH_ADDRLEN;
      if_info->has_media_address = 1;
    }
  else
    {
      if_info->media_addr_len = 0;
      if_info->has_media_address = 0;
    }

  /* MTU */
  if_info->mtu = ip6_ii->LinkMTU;
  if_info->has_mtu = 1;
}


static void
ssh_ipdev_ip6_decode_route(SshIpdevRouteInfo route,
                           IPV6_INFO_ROUTE_TABLE *ip6_ri)
{
  unsigned char mask[16];

  SSH_ASSERT(route != NULL);
  SSH_ASSERT(ip6_ri != NULL);

  memset(route, 0x00, sizeof(route));

  /* Set destination, mask, and next hop address */
  SSH_IP6_DECODE(&route->dest, &ip6_ri->This.Prefix);
  SSH_IP6_DECODE(&route->gw, &ip6_ri->This.Neighbor.Address);
  ssh_ip_net_mask_from_prefix_len(ip6_ri->This.PrefixLength, mask, 16);
  SSH_IP6_DECODE(&route->nm, mask);
  route->nm_len = ip6_ri->This.PrefixLength;

  /* Indexes */
  route->system_idx = ip6_ri->This.Neighbor.IF.Index;

  /* Determine route type */
  route->type = (SSH_IP_IS_NULLADDR(&route->gw)?
                 SSH_IP_ROUTE_DIRECT : SSH_IP_ROUTE_INDIRECT);

  route->metric = ip6_ri->Preference;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Dest: %@", ssh_ipaddr_render, &route->dest));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Mask: %@", ssh_ipaddr_render, &route->nm));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- NextHop: %@", ssh_ipaddr_render, &route->gw));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- IfIndex: %u", route->system_idx));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", ip6_ri->Type));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- SitePrefixLength: %u", ip6_ri->SitePrefixLength));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- ValidLiftime: %u", ip6_ri->ValidLifetime));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- PreferredLifetime: %u", ip6_ri->PreferredLifetime));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Preference: %u", ip6_ri->Preference));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Publish: %u", ip6_ri->Publish));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Immortal: %u", ip6_ri->Immortal));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("(- MTU: %u)", route->mtu));
}


static void
ssh_ipdev_ip6_decode_address(SshIpdevAddressInfo addr,
                             IPV6_INFO_ADDRESS *ip6_ai)
{
  unsigned char mask[16];

  memset(addr, 0x00, sizeof(*addr));

  addr->if_addr.protocol = SSH_PROTOCOL_IP6;
  SSH_IP6_DECODE(&addr->if_addr.addr.ip.ip, &ip6_ai->This.Address);
  addr->if_addr.addr.ip.ip.scope_id.scope_id_union.ui32 = ip6_ai->ScopeId;

  if (SSH_IP6_BYTE1(&addr->if_addr.addr.ip.ip) == 0x00)
    /* IPv6 addresses with embedded IPv4 addresses */
    ssh_ip_net_mask_from_prefix_len(96, mask, 16);
  else if (SSH_IP6_IS_SITE_LOCAL(&addr->if_addr.addr.ip.ip))
    ssh_ip_net_mask_from_prefix_len(64, mask, 16);
  else if (SSH_IP6_IS_LINK_LOCAL(&addr->if_addr.addr.ip.ip))
    ssh_ip_net_mask_from_prefix_len(10, mask, 16);
  else
    ssh_ip_net_mask_from_prefix_len(64, mask, 16);
  SSH_IP6_DECODE(&addr->if_addr.addr.ip.mask, mask);

  /* Set broadcast address to IPv6 undefined address */
  SSH_IP6_DECODE(&addr->if_addr.addr.ip.broadcast, 
                 SSH_IP6_UNDEFINED_ADDR);

  addr->system_idx = ip6_ai->This.IF.Index;
  addr->type = ip6_ai->Type;
  addr->dad_state = ip6_ai->DADState;
  addr->valid_lifetime = ip6_ai->ValidLifetime;
  addr->preferred_lifetime = ip6_ai->PreferredLifetime;
  addr->reasm_size = (SshUInt32)-1; /* Not used */
  addr->timestamp = (SshUInt32)-1; /* Not used */

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Address: %@", 
            ssh_ipaddr_render, &addr->if_addr.addr.ip.ip));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- ScopeID: %u", ip6_ai->ScopeId));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Mask: %@", 
            ssh_ipaddr_render, &addr->if_addr.addr.ip.mask));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Broadcast address: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.broadcast));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", addr->type));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Scope: %u", ip6_ai->Scope));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- DADState: %u", addr->dad_state));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- ValidLifetime: %u", addr->valid_lifetime));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- PreferredLifetime: %u", addr->preferred_lifetime));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- PrefixConf: %u", ip6_ai->PrefixConf));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- InterfaceIdConf: %u", ip6_ai->InterfaceIdConf));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- IsHomeAddress: %u", ip6_ai->IsHomeAddress));
}
#endif /* (WITH_IPV6) */


/*--------------------------------------------------------------------------
  Local Windows CE platform specific functions.
  --------------------------------------------------------------------------*/

static Boolean
ssh_ipdev_ip4_query_interfaces(SshIPDevice device,
                               SshIpdevInterfaceList if_list)
{
  Boolean status = FALSE;
  MIB_IFTABLE *if_table = NULL;
  DWORD api_status;
  ULONG required_size = 0;
  SshUInt32 i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(if_list != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Querying IPv4 interface table..."));

  /* Query the required size of buffer */
  api_status = GetIfTable(NULL, &required_size, TRUE);
  if ((api_status == ERROR_SUCCESS) || (required_size == 0))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to query size of IPv4 interface table"));
      goto error;
    }

  if_table = ssh_calloc(1, required_size);
  if (if_table == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate memory for IPv4 interface table"));
      goto error;
    }

  /* Query the MIB-II interface table */
  api_status = GetIfTable(if_table, &required_size, TRUE);
  if (api_status != ERROR_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to query IPv4 interface table"));
      goto error;
    }

  if_list->table = ssh_calloc(if_table->dwNumEntries, 
                              sizeof(SshIpdevInterfaceInfoStruct));
  if (if_list->table == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to allocate memory for IPv4 interfaces"));
      goto error;
    }

  for (i = 0; i < if_table->dwNumEntries; i++)
    {
      MIB_IFROW *if_row = &if_table->table[i];

      SSH_DEBUG(SSH_D_NICETOKNOW, ("----- IPv4 interface %u: -----", i));
      ssh_ipdev_ip4_decode_interface(&if_list->table[i], if_row);
    }

  /* Ok, now we have the interface table. */
  if_list->num_items = if_table->dwNumEntries;
  status = TRUE;

 error:
  ssh_free(if_table);

  return status;
}


static Boolean
ssh_ipdev_ip4_query_addresses(SshIPDevice device,
                              SshIpdevAddressList addr_list)
{
  Boolean status = FALSE;
  MIB_IPADDRTABLE *addr_table = NULL;
  DWORD api_status;
  ULONG required_size = 0;
  SshUInt32 i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_list != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Querying IPv4 address table..."));

  /* Query the required size of buffer */
  api_status = GetIpAddrTable(NULL, &required_size, TRUE);
  if ((api_status == ERROR_SUCCESS) || (required_size == 0))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to query size of IPv4 address table!"));
      goto error;
    }

  addr_table = ssh_calloc(1, required_size);
  if (addr_table == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to allocate memory for IPv4 address table!"));
      goto error;
    }

  /* Query the IPv4 address table */
  api_status = GetIpAddrTable(addr_table, &required_size, TRUE);
  if (api_status != ERROR_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to query IPv4 address table!"));
      goto error;
    }

  addr_list->table = ssh_calloc(addr_table->dwNumEntries, 
                              sizeof(SshIpdevAddressInfoStruct));
  if (addr_list->table == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to allocate memory for IPv4 addresses"));
      goto error;
    }

  for (i = 0; i < addr_table->dwNumEntries; i++)
    {
      MIB_IPADDRROW *ip_row = &addr_table->table[i];

      SSH_DEBUG(SSH_D_NICETOKNOW, ("----- IPv4 address %u: -----", i));
      ssh_ipdev_ip4_decode_address(&addr_list->table[i], ip_row);
    }

  /* Ok, now we have the interface table. */
  addr_list->num_items = addr_table->dwNumEntries;
  status = TRUE;

 error:
  ssh_free(addr_table);

  return status;
}


static Boolean
ssh_ipdev_ip4_query_routes(SshIPDevice device,
                           SshIpdevRouteList route_list)
{
  return TRUE;
}


static Boolean
ssh_ipdev_ip4_find_first_address(SshIPDevice device,
                                 SshIFIndex system_idx,
                                 SshAddressCtx *ctx_return)
{
  SshIpdevAddressInfo addr_table;
  unsigned int i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(ctx_return != NULL);

  ssh_kernel_rw_mutex_lock_read(&device->addr_lock);

  addr_table = device->addrs;

  for (i = 0; i < device->caddr; i++)
    {
      SshIpdevAddressInfo addr = &addr_table[i];

      if (addr->system_idx == system_idx)
        {
          *ctx_return = (SshAddressCtx)addr->address_id;
          ssh_kernel_rw_mutex_unlock_read(&device->addr_lock);
          return TRUE;
        }
    }

  ssh_kernel_rw_mutex_unlock_read(&device->addr_lock);

  return FALSE;
}


static Boolean
ssh_ipdev_configure_i(SshIPDevice device, 
                      SshIFIndex system_idx,
                      SshUInt16 configure_type, 
                      void *configure_params)
{
  /* Just a dummy, since this configure is not supported 
     on WinCE at the moment. Returns always success. */
  return TRUE;
}


static void
ssh_ipdev_ip4_clear_address(SshIPDevice device,
                            SshAddressCtx addr_ctx,
                            SshIPDeviceCompletionCB callback,
                            void *context)
{
  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_ctx != NULL);

  /* Perform callback processing (which will clear the address and rebind). */
  if (callback != NULL_FNPTR) 
    (*callback) (TRUE, context);
}


static void
ssh_ipdev_ip4_set_address(SshIPDevice device,
                          SshAddressCtx addr_ctx,
                          SshIpAddr ip,
                          SshIPDeviceCompletionCB callback,
                          void *context)
{
  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_ctx != 0);
  SSH_ASSERT(ip != NULL);

  /* Perform callback processing (which will configure the address 
     and rebind). */
  if (callback != NULL_FNPTR) 
    (*callback) (TRUE, context);
}


static void
ssh_ipdev_ip4_add_address(SshIPDevice device,
                          SshIFIndex system_idx,
                          SshInterceptorIfnum ifnum,
                          SshIpAddr ip,
                          SshAddressCtx *ctx_return,
                          SshIPDeviceCompletionCB callback,
                          void *context)
{
  Boolean status = FALSE;
  DWORD api_status;
  ULONG nte_context;
  ULONG nte_instance;
  IPAddr ip_addr;
  IPAddr ip_mask;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(ctx_return != NULL);

  SSH_IP4_ENCODE(ip, &ip_addr);
  ssh_ip_net_mask_from_prefix_len(ip->mask_len, 
                                  (unsigned char *)&ip_mask, 
                                  4);

  api_status = AddIPAddress(ip_addr, ip_mask, system_idx, 
                            &nte_context, &nte_instance);

  if (api_status == ERROR_SUCCESS)
    {
      *ctx_return = (SshAddressCtx)nte_context;
      status = TRUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to add IPv4 address (%08X)", api_status));
    }

  if (callback != NULL_FNPTR)
    (*callback)(status, context);
}


static void
ssh_ipdev_ip4_delete_address(SshIPDevice device,
                             SshAddressCtx addr_ctx,
                             SshIPDeviceCompletionCB callback,
                             void *context)
{
  BOOLEAN status = FALSE;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_ctx != NULL);

  if (DeleteIPAddress((ULONG)addr_ctx) == ERROR_SUCCESS)
    status = TRUE;

  if (callback != NULL_FNPTR)
    (*callback)(status, context);
}


#if defined (WITH_IPV6)

static Boolean
ssh_ipdev_ip6_query_interfaces(SshIPDevice device,
                               SshIpdevInterfaceList if_list)
{
  Boolean status = FALSE;
  SshIpdevInterfaceInfo decoded_copy = NULL;
  DWORD num_ifs = 0;
  unsigned int ioctl_counter;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(if_list != NULL);

  for (ioctl_counter = 0; ioctl_counter < 2; ioctl_counter++)
    {
      unsigned char buffer[2 * sizeof(IPV6_INFO_INTERFACE)];
      IPV6_INFO_INTERFACE *ip6_if = (IPV6_INFO_INTERFACE *)&buffer;
      IPV6_QUERY_INTERFACE id;
      DWORD bytes_read = 0;
      ULONG ioctl_code;
      BOOLEAN query_status;

      if (ioctl_counter == 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying non-persistent IPv6 interfaces..."));
          ioctl_code = IOCTL_IPV6_QUERY_INTERFACE;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying persistent IPv6 interfaces..."));
          ioctl_code = IOCTL_IPV6_PERSISTENT_QUERY_INTERFACE;
        }

      /* (1) Query the 1st interface identifier (index + GUID) */
      memset(&id, 0x00, sizeof(id));
      id.Index = -1;
      memset(ip6_if, 0x00, sizeof(*ip6_if));

      query_status = DeviceIoControl(device->context, 
                                     ioctl_code,
                                     &id, sizeof(id),
                                     buffer, sizeof(buffer), 
                                     &bytes_read, NULL);
      if (query_status == FALSE)
        {
          if (ioctl_code == IOCTL_IPV6_QUERY_INTERFACE)
            {
              if (bytes_read < sizeof(IPV6_QUERY_INTERFACE))
                {
                  SSH_DEBUG(SSH_D_FAIL, 
                            ("Failed to query first non-persistent "
                             "IPv6 interface"));
                  return FALSE;
                }
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("No persistent IPv6 interfaces; continuing..."));
              goto interfaces_read;
            }
        }

      /* (2) Query interface info for all IPv6 interfaces */
      status = query_status;
      while ((status != FALSE) && (ip6_if->Next.Index != (ULONG)-1))
        {
          id = ip6_if->Next;

          status = DeviceIoControl(device->context, 
                                   ioctl_code,
                                   &id, sizeof(id),
                                   buffer, sizeof(buffer), 
                                   &bytes_read, NULL);
          if (status != FALSE)
            {
              /* Collect results into interface array */
              size_t old_size = num_ifs * sizeof(*decoded_copy);
              size_t new_size = old_size + sizeof(*decoded_copy);
              SshIpdevInterfaceInfo old_ifs = decoded_copy;

              decoded_copy = ssh_realloc(old_ifs, old_size, new_size);
              if (decoded_copy == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Failed to allocate memory for IPv6 "
                             "interface."));
                  ssh_free(old_ifs);
                  status = FALSE;
                  break;
                }

              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("----- IPv6 interface %u: -----", num_ifs));
              ssh_ipdev_ip6_decode_interface(&decoded_copy[num_ifs], ip6_if);
              num_ifs++;
            }
          else
            {
              DWORD error = GetLastError();

              SSH_DEBUG(SSH_D_FAIL, 
                        ("IOCTL_IPV6_QUERY_INTERFACE request failed! (%08X)",
                        error));
            }
        }
    }

 interfaces_read:
  if (status != FALSE)
    {
      if_list->table = decoded_copy;
      if_list->num_items = num_ifs;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to read IPv6 interface information."));
      ssh_free(decoded_copy);
    }

  return status;
}


static Boolean
ssh_ipdev_ip6_query_addresses(SshIPDevice device,
                              SshIpdevAddressList addr_list)
{
  SshIpdevInterfaceListStruct if_list;
  SshIpdevAddressInfo decoded_copy = NULL;
  Boolean status = TRUE;
  ULONG num_addrs = 0;
  unsigned int ioctl_counter;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_list != NULL);

  RtlZeroMemory(&if_list, sizeof(if_list));
  if (!ssh_ipdev_ip6_query_interfaces(device, &if_list))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to query IPv6 interfaces"));
      return FALSE;
    }

  for (ioctl_counter = 0; ioctl_counter < 2; ioctl_counter++)
    {
      SshIpdevInterfaceInfo ifs = (SshIpdevInterfaceInfo)if_list.table;
      ULONG ioctl_code;
      unsigned int i;

      if (ioctl_counter == 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying non-persistent IPv6 addresses..."));
          ioctl_code = IOCTL_IPV6_QUERY_ADDRESS;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying persistent IPv6 addresses..."));
          ioctl_code = IOCTL_IPV6_PERSISTENT_QUERY_ADDRESS;
        }

      /* Query address info for all IPv6 interfaces */
      for (i = 0; i < if_list.num_items; i++)
        {
          SshIpdevInterfaceInfo ip6_if = &ifs[i];
          BOOL api_status;
          IPV6_QUERY_ADDRESS req;
          IPV6_INFO_ADDRESS addr;
          DWORD bytes_read = 0;

          /* Query first address ID (interface index + GUID + IPv6 address) */
          SSH_ASSERT(ip6_if->id.id_type == SSH_IF_ID_GUID);
          req.IF.Index = ip6_if->system_idx;
          req.IF.Guid  = ip6_if->id.u.guid;
          SSH_ASSERT(sizeof(req.Address) <= SSH_MAX_IP6_ADDR_LEN);
          memcpy(&req.Address, SSH_IP6_UNDEFINED_ADDR, SSH_MAX_IP6_ADDR_LEN);

          api_status = DeviceIoControl(device->context, 
                                       ioctl_code,
                                       &req, sizeof(req),
                                       &addr, sizeof(addr), 
                                       &bytes_read, NULL);

          if ((api_status == FALSE)
              && (ioctl_code == IOCTL_IPV6_PERSISTENT_QUERY_ADDRESS))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("No persistent IPv6 addresses; continuing..."));
              goto addresses_read;
            }

          /* Query all IPv6 addresses of this interface */
          while ((api_status != FALSE) &&
                 (bytes_read >= sizeof(IPV6_QUERY_ADDRESS)) &&
                 (memcmp(&addr.Next.Address,
                         SSH_IP6_UNDEFINED_ADDR,
                         SSH_MAX_IP6_ADDR_LEN) != 0))
            {
              req = addr.Next;

              api_status = DeviceIoControl(device->context,
                                           ioctl_code,
                                           &req, sizeof(req),
                                           &addr, sizeof(addr), 
                                           &bytes_read, NULL);
              if ((api_status != FALSE) 
                  && (bytes_read >= sizeof(addr)))
                {
                  /* Collect results into address array */
                  size_t addr_size = sizeof(*decoded_copy);
                  size_t old_size = num_addrs * addr_size;
                  size_t new_size = old_size + addr_size;
                  SshIpdevAddressInfo old_addrs = decoded_copy;

                  decoded_copy = ssh_realloc(old_addrs, old_size, new_size);
                  if (decoded_copy == NULL)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                             ("Failed to allocate memory for IPv6 "
                              "address."));
                      ssh_free(old_addrs);
                      status = FALSE;
                      break;
                    }

                  SSH_DEBUG(SSH_D_NICETOKNOW, 
                            ("----- IPv6 address %u: -----", num_addrs));
                  ssh_ipdev_ip6_decode_address(&decoded_copy[num_addrs], 
                                               &addr);
                  num_addrs++;
                }
            }
        }
    }

 addresses_read:
  /* Process results */
  if (status != FALSE)
    {
      addr_list->table = decoded_copy;
      addr_list->num_items = num_addrs;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to read IPv6 address information."));
      ssh_free(decoded_copy);
    }

  return status;
}


static Boolean
ssh_ipdev_ip6_query_routes(SshIPDevice device,
                           SshIpdevRouteList route_list)
{
  Boolean status = FALSE;
  SshIpdevRouteInfo decoded_copy = NULL;
  DWORD num_routes = 0;
  unsigned int ioctl_counter;

  for (ioctl_counter = 0; ioctl_counter < 2; ioctl_counter++)
    {
      IPV6_QUERY_ROUTE_TABLE req;
      IPV6_INFO_ROUTE_TABLE route_info;
      DWORD required_size;
      DWORD bytes_read = 0;
      ULONG ioctl_code;
      BOOLEAN query_status;

      if (ioctl_counter == 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying non-persistent IPv6 routes..."));
          ioctl_code = IOCTL_IPV6_QUERY_ROUTE_TABLE;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying persistent IPv6 routes..."));
          ioctl_code = IOCTL_IPV6_PERSISTENT_QUERY_ROUTE_TABLE;
        }
  
      /* Query the 1st route table entry index */
      memset(&req, 0x00, sizeof(req));
      memset(&route_info, 0x00, sizeof(route_info));
      required_size = sizeof(req);
      query_status = DeviceIoControl(device->context,
                                     ioctl_code,
                                     &req, sizeof(req),
                                     &route_info, sizeof(route_info),
                                     &bytes_read, NULL);
      if ((query_status == FALSE)
          && (ioctl_code == IOCTL_IPV6_PERSISTENT_QUERY_ROUTE_TABLE))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("No persistent IPv6 addresses; continuing..."));
          goto routes_read;
        }

      /* Query route info for all routing entries */
      status = query_status;
      req = route_info.Next;
      while ((status != FALSE) &&
             (req.Neighbor.IF.Index != 0L) &&
             (bytes_read == required_size))
        {
          memset(&route_info, 0x00, sizeof(route_info));
          required_size = sizeof(route_info);
          status = DeviceIoControl(device->context, 
                                   ioctl_code,
                                   &req, sizeof(req),
                                   &route_info, sizeof(route_info),
                                   &bytes_read, NULL);
          if (status != FALSE)
            {
              IPV6_QUERY_ROUTE_TABLE next_req = route_info.Next;

              if (req.Neighbor.IF.Index != 0)
                {
                  size_t route_info_size = sizeof(*decoded_copy);
                  size_t old_size = num_routes * route_info_size;
                  size_t new_size = old_size + route_info_size;
                  SshIpdevRouteInfo old_routes = decoded_copy;

                  /* Collect results into route array */
                  route_info.Next = req;
                  decoded_copy = ssh_realloc(old_routes, old_size, new_size);
                  if (decoded_copy == NULL)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Failed to allocate memory for IPv6 "
                                 "route."));
                      ssh_free(old_routes);
                      status = FALSE;
                      break;
                    }

                  SSH_DEBUG(SSH_D_NICETOKNOW, 
                            ("----- IPv6 route %u: -----", num_routes));
                  ssh_ipdev_ip6_decode_route(&decoded_copy[num_routes],
                                             &route_info);
                  num_routes++;
                }

              req = next_req;
            }
        }
    }

  /* Process results */
 routes_read:
  if (status != FALSE)
    {
      route_list->table = decoded_copy;
      route_list->num_items = num_routes;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to read IPv6 route table."));
      ssh_free(decoded_copy);
    }

  return status;
}

static void
ssh_ipdev_ip6_add_address_complete(void *context)
{
  SshIpv6UpdateAddress ctx = (SshIpv6UpdateAddress)context;

  if (ctx->callback != NULL_FNPTR)
    (*ctx->callback)(TRUE, ctx->context);
}

static void
ssh_ipdev_ip6_add_address(SshIPDevice device,
                          SshIFIndex system_idx,
                          SshInterceptorIfnum ifnum,
                          SshIpAddr ip,
                          SshAddressCtx *ctx_return,
                          SshIPDeviceCompletionCB callback,
                          void *context)
{
  SshIpv6UpdateAddress ctx;
  IPV6_UPDATE_ADDRESS *request;
  DWORD bytes_read;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(ctx_return != NULL);

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate memory for I/O request"));
      goto add_failed;
    }

  request = &ctx->request;
  request->This.IF.Index = system_idx;
  SSH_IP6_ENCODE(ip, &request->This.Address);
  request->Type = ADE_UNICAST;
  request->PrefixConf = PREFIX_CONF_MANUAL;
  request->InterfaceIdConf = IID_CONF_MANUAL;
  request->PreferredLifetime = INFINITE_LIFETIME;
  request->ValidLifetime = INFINITE_LIFETIME;

  if (DeviceIoControl(device->context,
                      IOCTL_IPV6_UPDATE_ADDRESS,
                      request, sizeof(*request),
                      NULL, 0, &bytes_read, NULL))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("IPv6 address %@ successfully added.",
                 ssh_ipaddr_render, ip));

      *ctx_return = request;

      /* We must wait until the IPv6 stack is ready to use this address.
         Unfortunately we don't get an address added indication on Windows
         CE so we schedule one second timeout and execute the completion
         callback when the timeout expires. */
      ctx->callback = callback;
      ctx->context = context;

      ssh_kernel_timeout_register(1, 0, 
                                  ssh_ipdev_ip6_add_address_complete, 
                                  ctx);
      return;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to add IPv6 address %@!", ssh_ipaddr_render, ip));

      ssh_free(request);
    }

 add_failed:
  *ctx_return = NULL;

  if (callback != NULL_FNPTR)
    (*callback)(FALSE, context);
}


static void
ssh_ipdev_ip6_delete_address(SshIPDevice device,
                             SshAddressCtx addr_ctx,
                             SshIPDeviceCompletionCB callback,
                             void *context)
{
  IPV6_UPDATE_ADDRESS *request = (IPV6_UPDATE_ADDRESS *)addr_ctx;
  BOOLEAN status = FALSE;
  DWORD bytes_read;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_ctx != NULL);

  request->PreferredLifetime = 0;
  request->ValidLifetime = 0;

  if (DeviceIoControl(device->context,
                      IOCTL_IPV6_UPDATE_ADDRESS,
                      request, sizeof(*request),
                      NULL, 0, &bytes_read, NULL))
    {
      status = TRUE;
    }

  if (callback != NULL_FNPTR)
    (*callback)(status, context);
}


static void
ssh_ipdev_ip6_add_route(SshIPDevice device,
                        SshIPRoute route,
                        SshIPDeviceCompletionCB callback,
                        void *context)
{
  Boolean status = FALSE;
  DWORD bytes_read;
  IPV6_INFO_ROUTE_TABLE request;
  unsigned int len;

  SSH_ASSERT(SSH_IP_DEFINED(&route->dest));

  memset(&request, 0x00, sizeof(request));
  SSH_IP_ENCODE(&route->dest, &request.This.Prefix, len);
  request.This.PrefixLength = route->nm_len;
  request.This.Neighbor.IF.Index = route->system_idx;
  SSH_IP_ENCODE(&route->gw, &request.This.Neighbor.Address, len);
  request.SitePrefixLength = 0;
  request.ValidLifetime = INFINITE_LIFETIME;    
  request.PreferredLifetime = INFINITE_LIFETIME;
  request.Preference = ROUTE_PREF_HIGHEST;
  request.Type = RTE_TYPE_MANUAL;
  request.Publish = 1;
  request.Immortal = 1;

  if (DeviceIoControl(device->context, 
                      IOCTL_IPV6_UPDATE_ROUTE_TABLE,
                      &request, sizeof(request),
                      NULL, 0, &bytes_read, NULL))
    {
      status = TRUE;
    }

  if (callback != NULL_FNPTR)
    (*callback)(status, context);
}


static void
ssh_ipdev_ip6_remove_route(SshIPDevice device,
                           SshIPRoute route,
                           SshIPDeviceCompletionCB callback,
                           void *context)
{
  Boolean status = FALSE;
  DWORD bytes_read;
  IPV6_INFO_ROUTE_TABLE request;
  unsigned int len;

  SSH_ASSERT(SSH_IP_DEFINED(&route->dest));

  memset(&request, 0x00, sizeof(request));
  SSH_IP_ENCODE(&route->dest, &request.This.Prefix, len);
  request.This.PrefixLength = route->nm_len;
  request.This.Neighbor.IF.Index = route->system_idx;
  SSH_IP_ENCODE(&route->gw, &request.This.Neighbor.Address, len);
  request.SitePrefixLength = 0;
  request.ValidLifetime = 0;    
  request.PreferredLifetime = 0;
  request.Preference = ROUTE_PREF_HIGHEST;
  request.Type = RTE_TYPE_MANUAL;
  request.Publish = 0;
  request.Immortal = 0;

  if (DeviceIoControl(device->context, 
                      IOCTL_IPV6_UPDATE_ROUTE_TABLE,
                      &request, sizeof(request),
                      NULL, 0, &bytes_read, NULL))
    {
      status = TRUE;
    }

  if (callback != NULL_FNPTR)
    (*callback)(status, context);
}

#endif /* WITH_IPV6 */

#endif /* _WIN32_WCE */
