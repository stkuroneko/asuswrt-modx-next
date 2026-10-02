/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   util_nameserver.h
*/

#ifndef _PM_UTIL_NAMESERVER_H_
#define _PM_UTIL_NAMESERVER_H_


/**********************************************************************
 * Callback function definitions.
 **********************************************************************/

/* Callback function for returning completion status.  `status' is true
   if the operation was successful and false if it failed. */
typedef void (*SshPmAddNameserverCB)(bool status, void * context);
typedef void (*SshPmRemoveNameserverCB)(bool status, void *context);


void ssh_pm_add_name_servers(int32_t num_dns,
                             SshIpAddr dns,
                             int32_t num_wins,
                             SshIpAddr wins,
                             SshPmAddNameserverCB callback,
                             void * context);
void ssh_pm_remove_name_servers(int32_t num_dns,
                             SshIpAddr dns,
                             int32_t num_wins,
                             SshIpAddr wins,
                             SshPmRemoveNameserverCB callback,
                             void * context);
#endif
