/**
   @copyright
   Copyright (c) 2010 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP address pool for allocating remote access IP addresses and
   parameters.
*/

#ifndef PM_REMOTE_ACCESS_DHCP_ADDRPOOL_H
#define PM_REMOTE_ACCESS_DHCP_ADDRPOOL_H

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_IPSEC_DHCP

#include "quicksec_pm.h"
#include "sshdhcp.h"

/* ************************* Types and definitions ***************************/
/* Parameter to define whether the DHCP address pool feature is enabled. */
#define SSH_DHCP_ADDRESS_POOL_ENABLED 1

#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED

/* The Vendor identifier class option string. (DHCP option 60). May be
   modified at will */
#define VENDOR_ID "ipsec.com"

/* The IANA private enterprise number for constructing the client DUID */
#define ENTERPRISE_NUMBER 123456

/* Internal DUID type. If zero or positive, will be added in front of the
   client id.
   May be modified at will. */
#define INTERNAL_DUID_TYPE -1

/* The requested DHCP lease time is twice the IKE SA lifetime, however
   not shorter than SSH_PM_DHCP_MIN_REQUESTED_LEASE_TIME. */
#define SSH_PM_DHCP_MIN_REQUESTED_LEASE_TIME (2 * SSH_PM_IKE_SA_MIN_LIFETIME)

/* Total time limit for DHCP operation. */
#define SSH_PM_DHCP_MAX_TOTAL_TIMEOUT  (SSH_PM_IKE_EXPIRE_TIMER_SECONDS / 2)

/* The size of the hash table for keeping track of already allocated
   IP addresses. */
#define SSH_DHCP_ALLOC_MAX SSH_PM_MAX_TUNNELS

/* ***************** Creating and destroying address pools *******************/

/** Create an address pool object.

    @return
    The function returns an address pool object, or NULL if the
    operation fails.
    */
SshPmAddressPool
ssh_pm_dhcp_address_pool_create(void);

/** Destroy the address pool 'addrpool'.

    @param addrpool
    The address pool to be destroyed.
*/
void
ssh_pm_dhcp_address_pool_destroy(SshPmAddressPool *addrpool);


/* ****************** Configuring attributes and addresses *******************/

/** Set the attributes for remote access clients. The address pool
    will include these attributes in the returned
    SshPmRemoteAccessAttrs of an allocation callback.

    @param own_ip_addr
    Specifies the gateway's own IP address used in PPP links. It can
    be left unspecified in which case the own IP address is not
    notified for PPP peers.

    @param dns
    The address of the DNS server in the private network. This
    attribute can be left unspecified, in which case the attribute is
    not sent for clients.

    @param wins
    The address of the WINS server (NetBIOS name server) in the
    private network. This attribute can be left unspecified, in
    which case the attribute is not sent for clients.

    @param dhcp
    The address of the DHCP server in the private network. This
    attribute can be left unspecified, in which case the attribute is
    not sent for clients.

    @return
    The function returns true if the the attributes were set, and
    false if the operation failed.

    */
bool
ssh_pm_dhcp_address_pool_set_attributes(
        SshPmAddressPool addrpool,
        const char *own_ip_addr,
        const char *dns,
        const char *wins,
        const char *dhcp);

/** Compare address pools.

    @param ap1
    The first address pool to be compared.

    @param ap2
    The second address pool to be compared.

    @return
    Returns true if the address pools are the same, else returns false.

*/
bool
ssh_pm_dhcp_address_pool_compare(SshPmAddressPool ap1, SshPmAddressPool ap2);

/* ******************** Allocating and freeing addresses *********************/
/** Allocate an IP address from the DHCP address pool 'addrpool'.

    @param addrpool
    The address pool from where the IP address is allocated.

    @param ad
    Contains authentication data of the IKE SA.

    @param flags
    Remote access allocation flags: renew or import.

    @param requested_attributes
    Contains the attributes requested by the remote access client.

    @param result_cb
    The callback to be called to pass the allocation result either
    synchronously or asynchronously.

    @param result_cb_context
    Context passed to 'result_cb'.

    @return
    This returns an operation handle.
    */
SshOperationHandle
ssh_pm_dhcp_address_pool_alloc_address(
                  SshPmAddressPool addrpool,
                  SshPmAuthData ad,
                  uint32_t flags,
                  SshPmRemoteAccessAttrs requested_attributes,
                  SshPmRemoteAccessAttrsAllocResultCB result_cb,
                  void *result_cb_context);

/** Get number of allocated addresses in an address pool.

    @param addrpool
    The address pool (DHCP server) the allocated addresses are from.

    @return
    The number of allocated addresses.
*/
uint32_t
ssh_pm_dhcp_address_pool_num_allocated_addresses(SshPmAddressPool addrpool);


/** Free IP address 'address' from the DHCP address pool 'addrpool'.

    @param addrpool
    The address pool from where the IP address is to be freed.

    @param address
    The address to be freed.

    @param data
    The parameters to be passed to the DHCP library.

    @return
    On error this return false, and otherwise true.
    */
bool
ssh_pm_dhcp_address_pool_free_address(SshPmAddressPool addrpool,
                                      const SshIpAddr address,
                                      void *data);

/** Expose statistics from the DHCP address pool 'addrpool'.

    @param addrpool
    The address pool from where the IP address is to be freed.

    @param stats
    The statistics output.

    @return
    If no DHCP statistics is available, this function returns false, and
    otherwise true.
    */
bool ssh_pm_dhcp_address_pool_get_statistics(SshPmAddressPool addrpool,
                                                SshPmAddressPoolStats stats);

#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
#endif /* SSHDIST_IPSEC_DHCP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* not PM_REMOTE_ACCESS_DHCP_ADDRPOOL_H */
