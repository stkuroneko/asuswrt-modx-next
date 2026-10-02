/**
   @copyright
   Copyright (c) 2009 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel mode IP routing table retrieval and modification functions
   for Windows CE based packet interceptor drivers.
*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "win_ip_route.h"

#ifdef _WIN32_WCE

#include <iphlpapi.h>

#define SSH_DEBUG_MODULE "SshInterceptorIPRoute"

static Boolean ssh_ip_route_lookup_ipv4(
  SshIpAddr destination, DWORD *ifindex, SshIpAddr nexthop, DWORD *mtu);
static Boolean ssh_ip_route_add_ipv4(SshIpAddr prefix, SshIpAddr nexthop);
static Boolean ssh_ip_route_remove_ipv4(SshIpAddr prefix, SshIpAddr nexthop);
static MIB_IPADDRTABLE *ssh_ip_route_get_ipaddrtable(void);
static MIB_IPFORWARDTABLE *ssh_ip_route_get_ipforwardtable(void);

static SshInterceptorIfnum
ssh_ip_route_ifnum(SshInterceptor interceptor, DWORD ifindex);

static int
ssh_ip_route_render_ipv4(
  unsigned char *buf, int buf_size, int precision, void *datum);

void __fastcall
ssh_ip_route_lookup_ce(
  SshInterceptor interceptor,
  SshInterceptorRouteKey key,
  SshInterceptorRouteCompletion completion,
  void *context)
{
  SshInterceptorIfnum ifnum;
  SshIpAddrStruct nexthop;
  DWORD ifindex, mtu;

  SSH_DEBUG(SSH_D_LOWOK,
    ("Looking up route to %@", ssh_ipaddr_render, &key->dst));

  if (!SSH_IP_IS4(&key->dst))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Non-IPv4 route support not included"));
      goto fail;
    }

  if (!ssh_ip_route_lookup_ipv4(&key->dst, &ifindex, &nexthop, &mtu))
    goto fail;

  /* Convert system interface index to toolkit ifnum. */
  ifnum = ssh_ip_route_ifnum(interceptor, ifindex);
  if (ifnum == SSH_INVALID_IFNUM)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown interface index"));
      goto fail;
    }

  SSH_DEBUG(SSH_D_LOWOK,
    ("Returning route to %@ via %@ ifnum %u mtu %u",
     ssh_ipaddr_render, &key->dst,
     ssh_ipaddr_render, &nexthop,
     (unsigned)ifnum,
     (unsigned)mtu));

  if (completion)
    completion(TRUE, &nexthop, ifnum, mtu, context);
  return;

 fail:
  if (completion)
    completion(FALSE, NULL, 0, 0, context);
}

void
ssh_ip_route_add_ce(
  SshInterceptor interceptor,
  SshIpAddr prefix,
  SshIpAddr nexthop,
  SshInterceptorIfnum ifnum,
  SshIPDeviceCompletionCB callback,
  void *context)
{
  Boolean ok = FALSE;

  SSH_DEBUG(SSH_D_MIDOK,
    ("Adding route to %@/%u via %@ ifnum %u",
     ssh_ipaddr_render, prefix,
     (unsigned)prefix->mask_len,
     ssh_ipaddr_render, nexthop,
     (unsigned)ifnum));

  if (prefix->type != nexthop->type)
    SSH_DEBUG(SSH_D_FAIL, ("Route prefix/nexthop IPv4/IPv6 mismatch"));
  else if (SSH_IP_IS4(prefix))
    ok = ssh_ip_route_add_ipv4(prefix, nexthop);
  else
    SSH_DEBUG(SSH_D_FAIL, ("Non-IPv4 route support not included"));

  if (callback)
    callback(ok, context);
}

void 
ssh_ip_route_remove_ce(
  SshInterceptor interceptor,
  SshIpAddr prefix,
  SshIpAddr nexthop,
  SshInterceptorIfnum ifnum,
  SshIPDeviceCompletionCB callback,
  void *context)
{
  Boolean ok = FALSE;

  SSH_DEBUG(SSH_D_MIDOK,
    ("Removing route to %@/%u via %@ ifnum %u",
     ssh_ipaddr_render, prefix,
     (unsigned)prefix->mask_len,
     ssh_ipaddr_render, nexthop,
     (unsigned)ifnum));

  if (prefix->type != nexthop->type)
    SSH_DEBUG(SSH_D_FAIL, ("Route prefix/nexthop IPv4/IPv6 mismatch"));
  else if (SSH_IP_IS4(prefix))
    ok = ssh_ip_route_remove_ipv4(prefix, nexthop);
  else
    SSH_DEBUG(SSH_D_FAIL, ("Non-IPv4 route support not included"));

  if (callback)
    callback(ok, context);
}

static Boolean ssh_ip_route_lookup_ipv4(
  SshIpAddr destination, DWORD *ifindex, SshIpAddr nexthop, DWORD *mtu)
{
  DWORD d, error;
  MIB_IPFORWARDROW ifr;

  SSH_IP4_ENCODE(destination, &d);
  error = GetBestRoute(d, 0, &ifr);
  if (error != NO_ERROR)
    {
      if (error == ERROR_CAN_NOT_COMPLETE)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("No route found"));
          return FALSE;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL,
            ("GetBestRoute: error 0x%08X", (unsigned)error));
          return FALSE;
        }
    }

  /* Do not consider local routes via loopback interfaces. */
  if (ifr.dwForwardProto == MIB_IPPROTO_LOCAL &&
      (ifr.dwForwardDest & ifr.dwForwardMask) !=
      (ifr.dwForwardNextHop & ifr.dwForwardMask))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Ignoring loopback route"));
      return FALSE;
    }

  *ifindex = ifr.dwForwardIfIndex;

  /* For directly connected destinatinations report the destination as
     the next hop. */
  if (ifr.dwForwardType == MIB_IPROUTE_TYPE_DIRECT)
    SSH_IP4_DECODE(nexthop, &d);
  else
    SSH_IP4_DECODE(nexthop, &ifr.dwForwardNextHop);

  /* No route MTU; use link MTU. */
  *mtu = 0;

  return TRUE;
}

static Boolean
ssh_ip_route_add_ipv4(SshIpAddr prefix, SshIpAddr nexthop)
{
  Boolean ok = FALSE;
  MIB_IPADDRTABLE *iat = NULL;
  MIB_IPADDRROW *iar;
  MIB_IPFORWARDTABLE *ift = NULL;
  MIB_IPFORWARDROW *ifr, new_ifr;
  DWORD error;
  unsigned int i, j;

  /* Get the table of local IP addresses and the route table. */

  if (!(iat = ssh_ip_route_get_ipaddrtable()) ||
      !(ift = ssh_ip_route_get_ipforwardtable()))
    goto end;

  /* Set up route destination, mask and next hop. */

  memset(&new_ifr, 0, sizeof new_ifr);

  SSH_IP4_ENCODE(prefix, &new_ifr.dwForwardDest);

  if (prefix->mask_len >= 32)
    new_ifr.dwForwardMask = 0xFFFFFFFFU;
  else
    SSH_PUT_32BIT(&new_ifr.dwForwardMask, ~(0xFFFFFFFFU >> prefix->mask_len));

  SSH_IP4_ENCODE(nexthop, &new_ifr.dwForwardNextHop);

  /* Find a local IP address that a) either is the next hop or belongs
     to the same network as the next hop and b) is up, i.e. has a
     local route in the routing table. Set route interface and
     type. */

  for (i = 0; i < (int)iat->dwNumEntries; i++)
    {
      iar = &iat->table[i];

      SSH_DEBUG(SSH_D_NICETOKNOW,
        ("Matching nexthop %@ with interface address %@/%@",
         ssh_ip_route_render_ipv4, &new_ifr.dwForwardNextHop,
         ssh_ip_route_render_ipv4, &iar->dwAddr,
         ssh_ip_route_render_ipv4, &iar->dwMask));

      /* Check L2 connectivity. */
      if (iar->dwAddr == new_ifr.dwForwardNextHop)
        {
          new_ifr.dwForwardIfIndex = iar->dwIndex;
          new_ifr.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
        }
      else if ((iar->dwAddr & iar->dwMask) ==
               (new_ifr.dwForwardNextHop & iar->dwMask))
        {
          new_ifr.dwForwardIfIndex = iar->dwIndex;
          new_ifr.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT;
        }
      else
        {
          continue;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
        ("Nexthop %@ is connected with interface address %@",
         ssh_ip_route_render_ipv4, &new_ifr.dwForwardNextHop,
         ssh_ip_route_render_ipv4, &iar->dwAddr));

      /* Find a local route for the local address. */
      for (j = 0; j < (int)ift->dwNumEntries; j++)
        {
          ifr = &ift->table[j];
          if (ifr->dwForwardProto == PROTO_IP_LOCAL &&
              ifr->dwForwardDest == iar->dwAddr)
            break;
        }
      if (j < (int)ift->dwNumEntries)
        break;

      SSH_DEBUG(
        SSH_D_NICETOKNOW,
        ("No local route found for interface address %@",
         ssh_ip_route_render_ipv4, &iar->dwAddr));
    }
  if (i >= (int)iat->dwNumEntries)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Next hop is not directly connected"));
      goto end;
    }

  /* Set the rest of route data. */

  new_ifr.dwForwardProto = PROTO_IP_NETMGMT;
  new_ifr.dwForwardMetric1 = 1;
  new_ifr.dwForwardMetric2 = MIB_IPROUTE_METRIC_UNUSED;
  new_ifr.dwForwardMetric3 = MIB_IPROUTE_METRIC_UNUSED;
  new_ifr.dwForwardMetric4 = MIB_IPROUTE_METRIC_UNUSED;
  new_ifr.dwForwardMetric5 = MIB_IPROUTE_METRIC_UNUSED;

  /* Add row. */

  error = CreateIpForwardEntry(&new_ifr);
  if (error != NO_ERROR)
    {
      SSH_DEBUG(SSH_D_FAIL,
        ("CreateIpForwardEntry: error 0x%08X", (unsigned)error));
      goto end;
    }

  ok = TRUE;

 end:
  if (ift)
    ssh_free(ift);
  if (iat)
    ssh_free(iat);

  return ok;
}

static Boolean
ssh_ip_route_remove_ipv4(SshIpAddr prefix, SshIpAddr nexthop)
{
  Boolean ok = FALSE;
  MIB_IPFORWARDTABLE *ift = NULL;
  MIB_IPFORWARDROW *ifr, the_ifr;
  DWORD error;
  unsigned int i;

  /* Get route table. */

  if (!(ift = ssh_ip_route_get_ipforwardtable()))
    goto end;

  /* Set up route destination, mask and next hop. */

  memset(&the_ifr, 0, sizeof the_ifr);

  SSH_IP4_ENCODE(prefix, &the_ifr.dwForwardDest);

  if (prefix->mask_len >= 32)
    the_ifr.dwForwardMask = 0xFFFFFFFFU;
  else
    SSH_PUT_32BIT(&the_ifr.dwForwardMask, ~(0xFFFFFFFFU >> prefix->mask_len));

  SSH_IP4_ENCODE(nexthop, &the_ifr.dwForwardNextHop);

  /* Find the route. Set route interface and type. */

  for (i = 0; i < (int)ift->dwNumEntries; i++)
    {
      ifr = &ift->table[i];
      if (ifr->dwForwardDest == the_ifr.dwForwardDest &&
          ifr->dwForwardMask == the_ifr.dwForwardMask &&
          ifr->dwForwardNextHop == the_ifr.dwForwardNextHop)
        {
          the_ifr.dwForwardIfIndex = ifr->dwForwardIfIndex;
          the_ifr.dwForwardType = ifr->dwForwardType;
          break;
        }
    }
  if (i >= (int)ift->dwNumEntries)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Route not found"));
      goto end;
    }

  /* Delete row. */

  error = DeleteIpForwardEntry(&the_ifr);
  if (error != NO_ERROR)
    {
      SSH_DEBUG(SSH_D_FAIL,
        ("DeleteIpForwardEntry: error 0x%08X", (unsigned)error));
      goto end;
    }

  ok = TRUE;

 end:
  if (ift)
    ssh_free(ift);

  return ok;
}

static MIB_IPADDRTABLE *
ssh_ip_route_get_ipaddrtable(void)
{
  MIB_IPADDRTABLE *data = NULL;
  DWORD error;
  ULONG size;

  size = 0;
  error = GetIpAddrTable(NULL, &size, FALSE);
  if (error != ERROR_INSUFFICIENT_BUFFER)
    {
      if (error == ERROR_NO_DATA)
        {
          SSH_DEBUG(SSH_D_FAIL, ("No local IP addresses"));
          return NULL;
        }
      SSH_DEBUG(SSH_D_FAIL, ("GetIpAddrTable: error 0x%08X", (unsigned)error));
      return NULL;
    }

  if (!(data = ssh_malloc(size)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("out of memory allocating IP address table"));
      return NULL;
    }

  error = GetIpAddrTable(data, &size, FALSE);
  if (error != NO_ERROR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("GetIpAddrTable: error 0x%08X", (unsigned)error));
      ssh_free(data);
      return NULL;
    }

  return data;
}

static MIB_IPFORWARDTABLE *
ssh_ip_route_get_ipforwardtable(void)
{
  MIB_IPFORWARDTABLE *data = NULL;
  DWORD error;
  ULONG size;

  size = 0;
  error = GetIpForwardTable(NULL, &size, FALSE);
  if (error != ERROR_INSUFFICIENT_BUFFER)
    {
      if (error == ERROR_NO_DATA)
        {
          SSH_DEBUG(SSH_D_FAIL, ("No IP routes"));
          return NULL;
        }
      SSH_DEBUG(SSH_D_FAIL,
        ("GetIpForwardTable: error 0x%08X", (unsigned)error));
      return NULL;
    }

  if (!(data = ssh_malloc(size)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("out of memory allocating IP route table"));
      return NULL;
    }

  error = GetIpForwardTable(data, &size, FALSE);
  if (error != NO_ERROR)
    {
      SSH_DEBUG(SSH_D_FAIL,
        ("GetIpForwardTable: error 0x%08X", (unsigned)error));
      ssh_free(data);
      return NULL;
    }

  return data;
}

static SshInterceptorIfnum
ssh_ip_route_ifnum(SshInterceptor interceptor, DWORD ifindex)
{
  SshInterceptorIfnum ifnum = SSH_INVALID_IFNUM;
  SshIPInterface ii;
  LIST_ENTRY *le;

  ssh_kernel_rw_mutex_lock_read(&interceptor->if_lock);

  for (le = interceptor->if_list.Flink;
       le != &interceptor->if_list;
       le = le->Flink)
    {
      ii = CONTAINING_RECORD(le, SshIPInterfaceStruct, link);

      if (ii->system_idx == ifindex)
        {
          ifnum = ii->adapter_ifnum;
          break;
        }
    }

  ssh_kernel_rw_mutex_unlock_read(&interceptor->if_lock);
  return ifnum;
}

static int
ssh_ip_route_render_ipv4(
  unsigned char *buf, int buf_size, int precision, void *datum)
{
  DWORD *dword = datum;
  SshIpAddrStruct address;
  int len;

  if (!dword)
    {
      ssh_snprintf(buf, buf_size + 1, "<null>");
    }
  else
    {
      SSH_IP4_DECODE(&address, dword);
      ssh_snprintf(buf, buf_size + 1, "%@", ssh_ipaddr_render, &address);
    }

  len = ssh_ustrlen(buf);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}

#endif /* _WIN32_WCE */
