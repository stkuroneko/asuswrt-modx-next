/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

#ifndef IP_SELECTOR_CONVERT_H
#define IP_SELECTOR_CONVERT_H

#include "public_defs.h"
#include "ip_selector.h"

struct SshIkev2PayloadTSRec;
struct SshSADHandleRec;


/**
   Function to return count of bytes required for encoding a
   IPSelectorGroup from a pair of IKEv2 Traffic Selectors.

   @param ike_local_ts
   Local traffic selector.

   @param ike_remote_ts
   Remote traffic selector.

   @return
   Count of bytes.
*/
int
ip_selector_convert_group_bytecount_ikev2ts(
        const struct SshIkev2PayloadTSRec *ike_local_ts,
        const struct SshIkev2PayloadTSRec *ike_remote_ts);


/**
   Function to convert IKEv2 Traffic selector pair to an
   IPSelectorGroup. The function does not allocate memory for the
   IPSelectorGroup. The caller provides the memory.

   @param selector_group
   Pointer to uninitialised block of memory where to encode the
   IPSelectorGroup. The block is expected to be of sufficient
   size. The required byte count can be fetched using function
   ip_selector_convert_group_bytecount_ikev2ts.

   @param selector_group_bytecount
   The size as byte count of the memory block pointed to by
   selector_group.

   @param ike_local_ts
   Local traffic selector.

   @param ike_remote_ts
   Remote traffic selector.
 */
void
ip_selector_convert_from_ikev2ts(
        struct IPSelectorGroup *selector_group,
        int selector_group_bytecount,
        const struct SshIkev2PayloadTSRec *ike_local_ts,
        const struct SshIkev2PayloadTSRec *ike_remote_ts);

/**
   Function to return count of bytes required for encoding a
   IPSelectorGroup from a pair of IKEv2 Traffic Selectors.

   @param sad_handle
   The SADHandle pointer used for IKEv2 Traffic Selector allocation.

   @param ike_local_ts_p
   Pointer to local traffic selector pointer. On success the local
   IKEv2 Traffic Selector is set here. Otherwise NULL.

   @param ike_remote_ts_p
   Pointer to remote traffic selector pointer. On success the remote
   IKEv2 Traffic Selector is set here. Otherwise NULL.

   @param ip_selector_group
   Pointer to the IPSelectorGroup to convert to IKEv2 Traffic
   Selectors. The IPSelectorGroup is expected to be IKEv2 Traffic
   selector compatible. That is, only it contains one IPSelector which
   in turn only contains IPSelectorEndpoints.

   @return
   Returns true on success and false, in failure.
*/
bool
ip_selector_convert_to_ikev2ts(
        struct SshSADHandleRec *sad_handle,
        struct SshIkev2PayloadTSRec **ike_local_ts_p,
        struct SshIkev2PayloadTSRec **ike_remote_ts_p,
        const struct IPSelectorGroup *ip_selector_group);


/**
   Function to check if an IPSelectorGroup is possible to convert to
   SshIkev2 traffic selector.

   @param ip_selector_group
   The selector group to check.

   @return
   Returns true if selector group is possible to convert or false
   otherwise.
*/
bool
ip_selector_convert_is_convertible(
        const struct IPSelectorGroup *ip_selector_group);

#endif /* IP_SELECTOR_CONVERT_H */
