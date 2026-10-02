/**
   @copyright
   Copyright (c) 2004 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   This offers the dns name server functions. It uses either internal
   dns resolver or system resolver depending on the configuration. It can
   also support other databases (/etc/hosts etc).
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshinet.h"
#ifdef SSHDIST_UTIL_DNS_RESOLVER
#include "sshdns.h"
#include "sshfileio.h"
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
#include "sshnameserver.h"
#include "sshglobals.h"











#if 0
#ifndef ENABLE_SYSTEM_DNS_RESOLVER
#define ENABLE_SYSTEM_DNS_RESOLVER 1
#endif /* ENABLE_SYSTEM_DNS_RESOLVER */
#endif

#define SSH_DEBUG_MODULE "SshNameServer"

#ifdef SSHDIST_UTIL_DNS_RESOLVER








#endif /* SSHDIST_UTIL_DNS_RESOLVER */

/* Internal global data. */
typedef struct SshNameServerDataRec {
  uint32_t timeout;            /* Timeout in useconds.  */
  bool use_system;
#ifdef SSHDIST_UTIL_DNS_RESOLVER
#ifndef ENABLE_SYSTEM_DNS_RESOLVER
  SshDNSResolver resolver;
  uint32_t resolver_find_flags;
#endif /* ENABLE_SYSTEM_DNS_RESOLVER */
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
} *SshNameServerData, SshNameServerDataStruct;

/* Global data. This is allocated in the ssh_name_server_init and freed by the
   ssh_name_server_uninit. */
SSH_GLOBAL_DECLARE(SshNameServerData, ssh_name_server_data);
#define ssh_name_server_data SSH_GLOBAL_USE(ssh_name_server_data)
SSH_GLOBAL_DEFINE(SshNameServerData, ssh_name_server_data);

/* Looks up all ip-addresses of the host, returning them as a
   comma-separated list when calling the callback.  The host name may
   already be an ip address, in which case it is returned directly. This uses
   the system resolver.  */
SshOperationHandle
ssh_tcp_get_host_addrs_by_name_system(const char *name,
                                      SshLookupCallback callback,
                                      void *context)
{
    char *addrs;

    addrs = ssh_tcp_get_host_addrs_by_name_sync(name);
    if (addrs)
    {
        callback(SSH_TCP_OK, addrs, context);
        ssh_free(addrs);
    }
    else
      callback(SSH_TCP_NO_ADDRESS, NULL, context);
    return NULL;
}

/* Looks up the name of the host by its ip-address.  Verifies that the
   address returned by the name servers also has the original ip address.
   Calls the callback with either error or success.  The callback should
   copy the returned name. This uses the system resolver. */
SshOperationHandle
ssh_tcp_get_host_by_addr_system(const char *addr,
                                SshLookupCallback callback,
                                void *context)
{
    char *name;

    name = ssh_tcp_get_host_by_addr_sync(addr);
    if (name)
    {
        callback(SSH_TCP_OK, name, context);
        ssh_free(name);
    }
    else
      callback(SSH_TCP_NO_ADDRESS, NULL, context);
    return NULL;
}

#ifdef SSHDIST_UTIL_DNS_RESOLVER
#ifndef ENABLE_SYSTEM_DNS_RESOLVER

/* Skip spaces. */
#define SKIP_SPACE(ptr, len) \
      while ((len) > 0 && isspace(*(ptr))) \
        { \
          (ptr)++; \
          (len)--; \
        }

#define FIND_SPACE(ptr, len) \
      while ((len) > 0 && !isspace(*(ptr))) \
        { \
          (ptr)++; \
          (len)--; \
        }

#define FIND_NEWLINE(ptr, len) \
      while ((len) > 0 && *(ptr) != '\n') \
        { \
          (ptr)++; \
          (len)--; \
        }

/* Read /etc/resolv.conf and configure the resolver from it. */
bool ssh_dns_resolver_read_resolv_conf(SshDNSResolver resolver,
                                          char *name)
{

    unsigned char *buffer;
    char *p, *q, c;
    SshIpAddrStruct address[1];
    size_t buffer_len;
    int i;

    if (!ssh_read_file_with_limit(name, 65536, &buffer, &buffer_len))
      return false;

    ssh_dns_resolver_safety_belt_clear(resolver);

    i = 0;
    p = (char *) buffer;
    while (buffer_len > 0)
    {
        SKIP_SPACE(p, buffer_len);
        if (buffer_len < 10)
          break;
        if (strncasecmp((char *)p, "nameserver", 9) == 0 && isspace(p[10]))
        {
            p += 10;
            buffer_len -= 10;
            SKIP_SPACE(p, buffer_len);
            q = p;
            FIND_SPACE(q, buffer_len);
            c = *q;
            *q = '\0';
            if (ssh_ipaddr_parse(address, p))
            {
                ssh_dns_resolver_safety_belt_add(resolver, 1, address);
                i++;
            }
            *q = c;
            p = q;
        }
        FIND_NEWLINE(p, buffer_len);
    }
    ssh_free(buffer);
    if (i == 0)
      return false;
    return true;





























}
#endif /* ENABLE_SYSTEM_DNS_RESOLVER */
#endif /* SSHDIST_UTIL_DNS_RESOLVER */

/* Initialize and configure the name server. */
bool ssh_name_server_init(SshNameServerConfig config)
{
#ifdef SSH_GLOBALS_EMULATION
    if (!SSH_GLOBAL_CHECK(ssh_name_server_data))
  {
      SSH_GLOBAL_INIT(ssh_name_server_data, NULL);
  }
#endif /* SSH_GLOBALS_EMULATION */

    if (ssh_name_server_data == NULL)
    {
        ssh_name_server_data = ssh_calloc(1, sizeof(*ssh_name_server_data));
        if (ssh_name_server_data == NULL)
          return false;
    }

#ifdef ENABLE_SYSTEM_DNS_RESOLVER
    /* Force to use system resolver. */
    ssh_name_server_data->use_system = true;
    return true;
#else /* ENABLE_SYSTEM_DNS_RESOLVER */
    if (config && config->use_system == true)
      ssh_name_server_data->use_system = true;

#ifdef SSHDIST_UTIL_DNS_RESOLVER
    ssh_name_server_data->timeout = 120000000;
    ssh_name_server_data->resolver_find_flags = 0;
    if (config && config->allow_non_authorative_data)
      ssh_name_server_data->resolver_find_flags |=
        SSH_DNS_RESOLVER_ALLOW_NON_AUTHORATIVE;
    if (config && config->forward_dns_queries)
      ssh_name_server_data->resolver_find_flags |=
        SSH_DNS_RESOLVER_ALLOW_NON_AUTHORATIVE |
        SSH_DNS_RESOLVER_START_FROM_SBELT |
        SSH_DNS_RESOLVER_RECURSIVE_REQUEST;

    if (config && config->timeout != 0)
      ssh_name_server_data->timeout = config->timeout;

    if (!ssh_name_server_data->use_system)
    {
        if (ssh_name_server_data->resolver != NULL)
        {
            if (config == NULL || config->ignore_default_safety_belt == false)
              ssh_dns_resolver_safety_belt_clear(
                      ssh_name_server_data->resolver);
        }
        else
        {
            ssh_name_server_data->resolver = ssh_dns_resolver_allocate();
        }
        if (ssh_name_server_data->resolver == NULL)
        {
            ssh_name_server_data->use_system = true;
            return false;
        }
        if (!ssh_dns_resolver_configure(ssh_name_server_data->resolver, NULL))
        {
            ssh_name_server_data->use_system = true;
            return false;
        }
        if (config == NULL || config->ignore_default_safety_belt == false)
        {




            if (!ssh_dns_resolver_read_resolv_conf(
                        ssh_name_server_data->
                        resolver,
                        "/etc/resolv.conf"))

            {
                SshIpAddrStruct localhost[1];

                SSH_IP_DECODE(localhost, "\x7f\x00\x00\x01", 4);
                ssh_dns_resolver_safety_belt_add(
                        ssh_name_server_data->resolver,
                        1, localhost);
#ifdef WITH_IPV6
                SSH_IP_DECODE(localhost, "\x00\x00\x00\x00\x00\x00\x00\x00"
                              "\x00\x00\x00\x00\x00\x00\x00\x01", 16);
                ssh_dns_resolver_safety_belt_add(
                        ssh_name_server_data->resolver,
                        1, localhost);
#endif /* WITH_IPV6 */
            }
        }
    }
#else /* SSHDIST_UTIL_DNS_RESOLVER */
    ssh_name_server_data->use_system = true;
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
    return true;
#endif /* ENABLE_SYSTEM_DNS_RESOLVER */
}

void ssh_name_server_shutdown(void)
{
#ifdef SSHDIST_UTIL_DNS_RESOLVER
#ifndef ENABLE_SYSTEM_DNS_RESOLVER
    if (ssh_name_server_data->resolver)
      ssh_dns_resolver_shutdown(ssh_name_server_data->resolver);
#endif /* ENABLE_SYSTEM_DNS_RESOLVER */
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
}

/* Unitialize the name server. */
void ssh_name_server_uninit(void)
{
    if (!ssh_name_server_data)
      return;
#ifdef SSHDIST_UTIL_DNS_RESOLVER
#ifndef ENABLE_SYSTEM_DNS_RESOLVER
    if (ssh_name_server_data->resolver)
      ssh_dns_resolver_free(ssh_name_server_data->resolver);
    ssh_name_server_data->resolver = NULL;
#endif /* ENABLE_SYSTEM_DNS_RESOLVER */
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
    ssh_free(ssh_name_server_data);
    ssh_name_server_data = NULL;
}

#ifdef SSHDIST_UTIL_DNS_RESOLVER
#ifndef ENABLE_SYSTEM_DNS_RESOLVER

/* Operation structure. */
typedef struct SshNameServerOperationRec {
  /* Handle to this operation. */
  SshOperationHandleStruct operation_handle[1];
  /* Lower level handle. */
  SshOperationHandle handle;
  /* Name we are searching for, this is mallocated. */
  char *dns_name;
  /* Length of the name if reverse lookup. */
  size_t length;
  /* Return callback. */
  SshLookupCallback callback;
  /* Return context. */
  void *context;
  /* Temp rrset, this needs to be unlocked if not null. */
  SshDNSRRset rrset;
  /* Did we got timeout during the operation. */
  bool timed_out;
  /* Flags to the ssh_dns_resolver_find. */
  uint32_t flags;
} *SshNameServerOperation, SshNameServerOperationStruct;

/* Abort the operation. */
void ssh_name_server_result_abort(void *context)
{
    SshNameServerOperation operation = context;

    /* Abort lower level operations. */
    if (operation->handle != NULL)
      ssh_operation_abort(operation->handle);
    operation->handle = NULL;

    if (operation->rrset)
    {
        SshDNSRRsetCache rrset_cache;

        rrset_cache =
          ssh_dns_resolver_rrset_cache(ssh_name_server_data->resolver);
        ssh_dns_rrset_cache_unlock(rrset_cache, operation->rrset);
        operation->rrset = NULL;
    }

    ssh_free(operation->dns_name);
    ssh_free(operation);
}

/* Clean up after the operation is finished. */
void ssh_name_server_result_end(SshNameServerOperation operation)
{
    ssh_operation_unregister(operation->operation_handle);
    if (operation->rrset)
    {
        SshDNSRRsetCache rrset_cache;

        rrset_cache =
          ssh_dns_resolver_rrset_cache(ssh_name_server_data->resolver);
        ssh_dns_rrset_cache_unlock(rrset_cache, operation->rrset);
        operation->rrset = NULL;
    }
    ssh_free(operation->dns_name);
    ssh_free(operation);
}

/* Parse the result of the AAAA query, and call callback. */
void ssh_name_server_result_aaaa(SshDNSResponseCode error,
                                 SshDNSRRset rrset,
                                 void *context)
{
    SshNameServerOperation operation = context;
    unsigned char internal_buffer[256];
    char *buffer, *p;
    SshIpAddrStruct address[1];
    size_t len;
    int i;

    operation->handle = NULL;

    if (error == SSH_DNS_OK && rrset != NULL)
    {
        if (rrset->state == SSH_DNS_RRSET_NODATA)
        {
            rrset = NULL;
        }
    }
    else
    {
        rrset = NULL;
    }
    if (error == SSH_DNS_TIMEOUT)
      operation->timed_out = true;

    len = 0;
    if (operation->rrset)
    {
        /* Count number of ipv4 addresses. Each address takes 16 bytes
           + comma. */
        len += operation->rrset->number_of_rrs * 17;
    }
    if (rrset)
    {
        /* Count number of ipv6 addresses. Each address takes 40 bytes
           + comma. */
        len += rrset->number_of_rrs * 41;
    }
    if (len >= sizeof(internal_buffer))
    {
        buffer = ssh_malloc(len);
        if (buffer == NULL)
        {
            operation->callback(SSH_TCP_FAILURE, buffer, operation->context);
            goto out;
        }
    }
    else
    {
        buffer = (char *) internal_buffer;
    }

    p = buffer;
    if (operation->rrset)
    {
        for(i = 0; i < operation->rrset->number_of_rrs; i++)
        {
            if (operation->rrset->array_of_rdlengths[i] != 4)
              continue;
            SSH_IP_DECODE(address, operation->rrset->array_of_rdata[i],
                          operation->rrset->array_of_rdlengths[i]);
            ssh_ipaddr_print(address, p, buffer + len - p);
            p += strlen((char *)p);
            *p++ = ',';
        }
    }
    if (rrset)
    {
        for(i = 0; i < rrset->number_of_rrs; i++)
        {
            if (rrset->array_of_rdlengths[i] != 16)
              continue;
            SSH_IP_DECODE(address, rrset->array_of_rdata[i],
                          rrset->array_of_rdlengths[i]);
            ssh_ipaddr_print(address, p, buffer + len - p);
            p += strlen((char *)p);
            *p++ = ',';
        }
    }
    if (p != buffer)
    {
        p--;
    }
    *p = '\0';
    if (strlen((char *)buffer) == 0)
      operation->callback(operation->timed_out ? SSH_TCP_TIMEOUT :
                          SSH_TCP_NO_ADDRESS, NULL, operation->context);
    else
      operation->callback(SSH_TCP_OK, buffer, operation->context);
    if (len >= sizeof(internal_buffer))
      ssh_free(buffer);
   out:
    ssh_name_server_result_end(operation);
}

/* Parse the result of A query, and start the AAAA query. */
void ssh_name_server_result_a(SshDNSResponseCode error,
                              SshDNSRRset rrset,
                              void *context)
{
    SshNameServerOperation operation = context;

    operation->handle = NULL;

    if (error == SSH_DNS_OK)
    {
        if (rrset->state == SSH_DNS_RRSET_NODATA)
        {
            /* No data, so there cannot be IPv6 address either. */
            operation->callback(SSH_TCP_NO_ADDRESS, NULL, operation->context);
            ssh_name_server_result_end(operation);
            return;
        }
        else
        {
            /* It must be authorative data, lock it. */
            SshDNSRRsetCache rrset_cache;
            rrset_cache =
              ssh_dns_resolver_rrset_cache(ssh_name_server_data->resolver);
            ssh_dns_rrset_cache_lock(rrset_cache, rrset);
            operation->rrset = rrset;
        }
    }
    else
    {
        if (error == SSH_DNS_TIMEOUT)
          operation->timed_out = true;
    }
#ifdef WITH_IPV6
    /* Try to find IPv6 address. */
    operation->handle =
        ssh_dns_resolver_find(
                ssh_name_server_data->resolver,
                operation->dns_name,
                SSH_DNS_RESOURCE_AAAA,
                ssh_name_server_data->timeout,
                operation->flags,
                ssh_name_server_result_aaaa,
                operation);
#else /* WITH_IPV6 */
    ssh_name_server_result_aaaa(SSH_DNS_OK, NULL, operation);
#endif /* WITH_IPV6 */
}

/* Does the name server lookup using internal dns resolver. */
SshOperationHandle
ssh_tcp_get_host_addrs_by_name_dns(
        const char *name,
        SshLookupCallback callback,
        void *context)
{
    SshNameServerOperation operation;
    char *dns_name;
    char *p, *q;
    size_t len;

    operation = ssh_calloc(1, sizeof(*operation));
    if (operation == NULL)
    {
        callback(SSH_TCP_FAILURE, NULL, context);
        return NULL;
    }

    /* Convert the name to dns format. */
    dns_name = ssh_malloc(strlen((char *)name) + 2);
    if (dns_name == NULL)
    {
        ssh_free(operation);
        callback(SSH_TCP_FAILURE, NULL, context);
        return NULL;
    }
    ssh_strcpy(dns_name + 1, name);
    q = dns_name;
    while ((p = ssh_strchr(q + 1, '.')) != NULL)
    {
        len = (p - q) - 1;
        if (len > 63)
        {
            ssh_free(dns_name);
            ssh_free(operation);
            callback(SSH_TCP_FAILURE, NULL, context);
            return NULL;
        }
        *q = (char) len;
        q = p;
    }
    len = strlen((char *)q + 1);
    if (len > 63)
    {
        ssh_free(dns_name);
        ssh_free(operation);
        callback(SSH_TCP_FAILURE, NULL, context);
        return NULL;
    }
    *q = (char) len;

    operation->callback = callback;
    operation->context = context;
    operation->dns_name = dns_name;
    operation->timed_out = false;
    operation->flags = ssh_name_server_data->resolver_find_flags;

    ssh_operation_register_no_alloc(operation->operation_handle,
                                    ssh_name_server_result_abort,
                                    operation);

    /* Ok, the name is now ready, start query. */
    operation->handle =  ssh_dns_resolver_find(ssh_name_server_data->resolver,
                                               dns_name, SSH_DNS_RESOURCE_A,
                                               ssh_name_server_data->timeout,
                                               operation->flags,
                                               ssh_name_server_result_a,
                                               operation);
    return operation->operation_handle;
}

/* Parse the reply of the either A or AAAA query, depending of the original PTR
   query name. Call the result callback. */
void ssh_name_server_result_forward(SshDNSResponseCode error,
                                    SshDNSRRset rrset,
                                    void *context)
{
    SshNameServerOperation operation = context;
    unsigned char internal_buffer[256];
    char *buffer;
    size_t len;
    int i;

    operation->handle = NULL;

    if (error == SSH_DNS_OK && rrset != NULL)
    {
        if (rrset->state == SSH_DNS_RRSET_NODATA)
        {
            rrset = NULL;
        }
    }
    else
    {
        rrset = NULL;
    }

    /* If we didn't find the name, then return error. */
    if (rrset == NULL)
    {
        if (error == SSH_DNS_TIMEOUT)
          operation->timed_out = true;
        operation->callback(operation->timed_out ? SSH_TCP_TIMEOUT :
                            SSH_TCP_NO_NAME, NULL, operation->context);
        ssh_name_server_result_end(operation);
        return;
    }

    /* Verify that the original ip-address we are searching for is also in the
       forward map. */
    for(i = 0; i < rrset->number_of_rrs; i++)
    {
        if (rrset->array_of_rdlengths[i] == operation->length &&
            memcmp(rrset->array_of_rdata[i], operation->dns_name,
                   operation->length) == 0)
          break;
    }
    if (i == rrset->number_of_rrs)
    {
        /* Didn't find the original ip from the forward map. */
        operation->callback(SSH_TCP_NO_NAME, NULL, operation->context);
        ssh_name_server_result_end(operation);
        return;
    }

    len = strlen((char *)operation->rrset->array_of_rdata[0]) + 1;
    if (len >= sizeof(internal_buffer))
    {
        buffer = ssh_malloc(len);
        if (buffer == NULL)
        {
            operation->callback(SSH_TCP_FAILURE, NULL, operation->context);
            ssh_name_server_result_end(operation);
            return;
        }
    }
    else
    {
        buffer = (char *) internal_buffer;
    }

    ssh_snprintf(buffer, len, "%@", ssh_dns_name_render,
                 operation->rrset->array_of_rdata[0]);
    /* Remove the final dot. */
    i = strlen((char *)buffer);
    if (i > 0 && buffer[i - 1] == '.')
      buffer[i - 1] = '\0';

    /* Call the result callback now. */
    operation->callback(SSH_TCP_OK, buffer, operation->context);
    if (len >= sizeof(internal_buffer))
      ssh_free(buffer);
    ssh_name_server_result_end(operation);
    return;
}

void ssh_name_server_result_ptr(SshDNSResponseCode error,
                                SshDNSRRset rrset,
                                void *context)
{
    SshNameServerOperation operation = context;
    SshDNSRRsetCache rrset_cache;

    operation->handle = NULL;

    if (error != SSH_DNS_OK ||
        rrset->state == SSH_DNS_RRSET_NODATA ||
        rrset->number_of_rrs == 0)
    {
        /* No data. */
        if (error == SSH_DNS_TIMEOUT)
          operation->timed_out = true;
        operation->callback(operation->timed_out ?
                            SSH_TCP_TIMEOUT :
                            SSH_TCP_NO_NAME, NULL, operation->context);
        ssh_name_server_result_end(operation);
        return;
    }

    /* It must be authorative data, lock it. */
    rrset_cache = ssh_dns_resolver_rrset_cache(ssh_name_server_data->resolver);
    ssh_dns_rrset_cache_lock(rrset_cache, rrset);
    operation->rrset = rrset;
    /* Do the forward lookup. */
    operation->handle =
      ssh_dns_resolver_find(ssh_name_server_data->resolver,
                            rrset->array_of_rdata[0],
                            operation->length == 4 ?
                            SSH_DNS_RESOURCE_A :
                            SSH_DNS_RESOURCE_AAAA,
                            ssh_name_server_data->timeout,
                            operation->flags, ssh_name_server_result_forward,
                            operation);
    return;
}

/* Does the name server lookup using internal dns resolver. */
SshOperationHandle
ssh_tcp_get_host_by_addr_dns(
        const char *name,
        SshLookupCallback callback,
        void *context)
{
    SshNameServerOperation operation;
    char *dns_name, *p;
    unsigned char buffer[16];
    size_t len;
    int i;

    len = 16;
    if (!ssh_inet_strtobin(name, buffer, &len))
    {
        callback(SSH_TCP_FAILURE, NULL, context);
        return NULL;
    }

    operation = ssh_calloc(1, sizeof(*operation));
    if (operation == NULL)
    {
        callback(SSH_TCP_FAILURE, NULL, context);
        return NULL;
    }

    operation->dns_name = ssh_memdup(buffer, len);
    if (operation->dns_name == NULL)
    {
        ssh_free(operation);
        callback(SSH_TCP_FAILURE, NULL, context);
        return NULL;
    }

    if (len == 4)
    {
        /* IPv4 address, convert a.b.c.d to d.c.b.a.in-addr.arpa. Buffer size
           needed is 15 + 13 + 1 = 29. */
        dns_name = ssh_malloc(32);
        if (dns_name == NULL)
        {
            ssh_free(operation);
            callback(SSH_TCP_FAILURE, NULL, context);
            return NULL;
        }
        p = dns_name;
        for(i = 3; i >= 0; i--)
        {
            if (buffer[i] >= 100)
              *p = 3;
            else if (buffer[i] >= 10)
              *p = 2;
            else
              *p = 1;
            ssh_snprintf(p + 1, dns_name + 32 - p - 1,
                         "%d", buffer[i]);
            p += (*p) + 1;
        }
        strcpy((char *)p, "\7in-addr\4arpa");
    }
    else
    {
        /* IPv6 address, convert it to
           p.o.n.m.l.k.j.i.h.g.f.e.d.c.b.a.p.o.n.m.l.k.j.i.h.g.f.e.d.c.b.a.
           ip6.arpa.
           Buffer size needed is 32 * 2 + 9 = 73. */
        dns_name = ssh_malloc(80);
        if (dns_name == NULL)
        {
            ssh_free(operation);
            callback(SSH_TCP_FAILURE, NULL, context);
            return NULL;
        }
        p = dns_name;
        for(i = 15; i >= 0; i--)
        {
            *p++ = 1;
            *p++ = "0123456789abcdef"[buffer[i] & 0xf];
            *p++ = 1;
            *p++ = "0123456789abcdef"[buffer[i] >> 4];
        }
        strcpy((char *)p, "\3ip6\4arpa");
    }

    operation->callback = callback;
    operation->context = context;
    operation->length = len;
    operation->timed_out = false;
    operation->flags = ssh_name_server_data->resolver_find_flags;

    ssh_operation_register_no_alloc(operation->operation_handle,
                                    ssh_name_server_result_abort,
                                    operation);

    /* Ok, the name is now ready, start query. */
    operation->handle =  ssh_dns_resolver_find(ssh_name_server_data->resolver,
                                               dns_name, SSH_DNS_RESOURCE_PTR,
                                               ssh_name_server_data->timeout,
                                               operation->flags,
                                               ssh_name_server_result_ptr,
                                               operation);
    ssh_free(dns_name);
    return operation->operation_handle;
}

#endif /* ENABLE_SYSTEM_DNS_RESOLVER */
#endif /* SSHDIST_UTIL_DNS_RESOLVER */

/* Looks up all ip-addresses of the host, returning them as a
   comma-separated list when calling the callback.  The host name may
   already be an ip address, in which case it is returned directly. */
SshOperationHandle
ssh_tcp_get_host_addrs_by_name(const char *name,
                               SshLookupCallback callback,
                               void *context)
{
    SshIpAddrStruct address[1];

    if (ssh_name_server_data == NULL)
      ssh_name_server_init(NULL);

    /* Check if it is IPv6 address in [addr] format. */
    if (*name == '[')
    {
        char *ret;
        size_t len;

        ret = ssh_strdup(name + 1);
        if (ret == NULL)
        {
            callback(SSH_TCP_FAILURE, NULL, context);
            return NULL;
        }
        len = strlen((char *)ret);
        if (len > 0)
        {
            if (ret[len - 1] == ']')
            {
                ret[len - 1] = '\0';
                if (ssh_ipaddr_parse(address, ret))
                {
                    callback(SSH_TCP_OK, ret, context);
                    ssh_free(ret);
                    return NULL;
                }
            }
        }
        ssh_free(ret);
    }
    /* First check if it is already an ip address. */
    if (ssh_ipaddr_parse(address, name))
    {
        callback(SSH_TCP_OK, name, context);
        return NULL;
    }

    if (strcasecmp((char *)name, "localhost") == 0 ||
        strcasecmp((char *)name, "localhost.") == 0)
    {
#ifdef WITH_IPV6
        callback(SSH_TCP_OK, "127.0.0.1,::1", context);
#else /* WITH_IPV6 */
        callback(SSH_TCP_OK, "127.0.0.1", context);
#endif /* WITH_IPV6 */
        return NULL;
    }

#ifdef SSHDIST_UTIL_DNS_RESOLVER
#ifndef ENABLE_SYSTEM_DNS_RESOLVER
    if (ssh_name_server_data && !ssh_name_server_data->use_system)
      return ssh_tcp_get_host_addrs_by_name_dns(name, callback, context);
#endif /* ENABLE_SYSTEM_DNS_RESOLVER */
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
    return ssh_tcp_get_host_addrs_by_name_system(name, callback, context);
}

/* Looks up the name of the host by its ip-address.  Verifies that the
   address returned by the name servers also has the original ip address.
   Calls the callback with either error or success.  The callback should
   copy the returned name. */
SshOperationHandle
ssh_tcp_get_host_by_addr(const char *addr,
                         SshLookupCallback callback,
                         void *context)
{
    unsigned char buffer[16];
    size_t len;

    if (ssh_name_server_data == NULL)
      ssh_name_server_init(NULL);

    len = 16;
    if (!ssh_inet_strtobin(addr, buffer, &len))
    {
        callback(SSH_TCP_FAILURE, NULL, context);
        return NULL;
    }
    if ((len == 4 && memcmp(buffer, "\x7f\x00\x00\x01", 4) == 0) ||
        (len == 16 &&
         memcmp(buffer, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16) == 0))
    {
        callback(SSH_TCP_OK, "localhost", context);
        return NULL;
    }

#ifdef SSHDIST_UTIL_DNS_RESOLVER
#ifndef ENABLE_SYSTEM_DNS_RESOLVER
    if (ssh_name_server_data && !ssh_name_server_data->use_system)
      return ssh_tcp_get_host_by_addr_dns(addr, callback, context);
#endif /* ENABLE_SYSTEM_DNS_RESOLVER */
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
    return ssh_tcp_get_host_by_addr_system(addr, callback, context);
}

#ifdef SSHDIST_UTIL_DNS_RESOLVER
SshDNSResolver ssh_name_server_resolver(void)
{
    if (ssh_name_server_data == NULL)
      ssh_name_server_init(NULL);
    if (ssh_name_server_data == NULL)
      return NULL;
#ifndef ENABLE_SYSTEM_DNS_RESOLVER
    return ssh_name_server_data->resolver;
#else /* ENABLE_SYSTEM_DNS_RESOLVER */
    return NULL;
#endif /* ENABLE_SYSTEM_DNS_RESOLVER */
}
#endif /* SSHDIST_UTIL_DNS_RESOLVER */


#ifdef SSHDIST_UTIL_DNS_RESOLVER

















































































































































































































































































































#endif /* SSHDIST_UTIL_DNS_RESOLVER */
