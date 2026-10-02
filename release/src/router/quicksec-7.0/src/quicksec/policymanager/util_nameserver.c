/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Configures DNS and WINS addresses obtained though ISAKMP Exchange.
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshfileio.h"
#include "util_nameserver.h"

#ifdef SSHDIST_UTIL_DNS_RESOLVER
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshdns.h"
#endif /* SSHDIST_UTIL_DNS_RESOLVER */














#define SSH_DEBUG_MODULE "SshPmUtilNameServer"


















































































































































































































































































































































































































































































































































































































































































































































#define START_VIRTUAL_CONNECT_IDENT "#nameservers obtained through virtual"\
                                    " connection\n"
#define END_VIRTUAL_CONNECT_IDENT "#end of virtual connection section\n"


/* On Linux the contents are written to /etc/resolv.conf file. The DNS
   entries are added so as to maintain the structure of the existing
   file. Markers as comments are inserted so that these entries can be
   removed when the virtual tunnel is shutdown */

static void
ssh_net_add_name_server_unix(int32_t num_dns,
                             SshIpAddr dns,
                             SshPmAddNameserverCB callback,
                             void *context)
{
    unsigned char *file_content, *buffer = NULL;
    size_t content_len, buffer_len = 0;
    bool success = false;
    int i, len;
    char one_line[80] = {0};
    unsigned char *curr_pos;

    if (!ssh_read_file_with_limit("/etc/resolv.conf", 65536,
                                  &file_content, &content_len))
      { /* Maybe the file does not exist. Try to create one */
        file_content = NULL;
        content_len = 0;
    }
    buffer = ssh_calloc(1, content_len + 1024);
    if (buffer == NULL)
      goto exit_func;

    memcpy (buffer, START_VIRTUAL_CONNECT_IDENT,
                    strlen(START_VIRTUAL_CONNECT_IDENT));
    buffer_len += strlen(START_VIRTUAL_CONNECT_IDENT);

    curr_pos = buffer + buffer_len;
    for (i = 0; i < num_dns; curr_pos += len, i++)
    {
        len = ssh_snprintf(one_line, sizeof(one_line), "%s\t%@\n",
                                   "nameserver",
                                   ssh_ipaddr_render, &dns[i]);
        memcpy(curr_pos, one_line, len);
        buffer_len += len;
    }

    memcpy(buffer + buffer_len, END_VIRTUAL_CONNECT_IDENT,
                      strlen(END_VIRTUAL_CONNECT_IDENT));

    buffer_len += strlen(END_VIRTUAL_CONNECT_IDENT);

    if (file_content != NULL)
    {
        memcpy(buffer + buffer_len, file_content, content_len);
    }

    buffer_len += content_len;

    if (ssh_write_file("/etc/resolv.conf", buffer, buffer_len))
      success = true;

  exit_func:
    if (file_content)
      ssh_free(file_content);
    if (buffer)
      ssh_free(buffer);

    if (callback != NULL_FNPTR)
      (*callback)(success, context);
}

static void
ssh_net_remove_name_server_unix(SshPmRemoveNameserverCB callback,
                                void *context)
{
    unsigned char *file_content = NULL;
    char *buffer = NULL;
    size_t content_len, buf_len;
    bool success = true;
    char *dest;
    size_t tail_len;

    if (!ssh_read_file_with_limit("/etc/resolv.conf",65536,
                                   &file_content, &content_len))
    {
        success = false;
        goto exit_func;
    }

    buffer = ssh_memdup(file_content, content_len);
    buf_len = content_len;
    if (NULL == buffer)
    {
        success = false;
        goto exit_func;
    }

    memset(file_content, 0, content_len);

    dest = strstr(buffer, START_VIRTUAL_CONNECT_IDENT);
    if (NULL == dest)
      goto exit_func;

    content_len = dest - buffer;
    memcpy(file_content, buffer, content_len);

    dest = strstr(buffer, END_VIRTUAL_CONNECT_IDENT);

    if (NULL == dest)
    {
        success = false;
        goto exit_func;
    }

    dest += strlen(END_VIRTUAL_CONNECT_IDENT);

    if (dest >= buffer + buf_len)
    {
        success = false;
        goto exit_func;
    }

    tail_len = buffer + buf_len - dest;

    memcpy(
            file_content + content_len,
            dest,
            tail_len);

    content_len += tail_len;

    if (!ssh_write_file("/etc/resolv.conf", file_content, content_len))
      success = false;

  exit_func:
    if (file_content)
      ssh_free(file_content);
    if (buffer)
      ssh_free(buffer);

    if (callback != NULL_FNPTR)
      (*callback)(success, context);
}


void
ssh_pm_add_name_servers(int32_t num_dns,
                        SshIpAddr dns,
                        int32_t num_wins,
                        SshIpAddr wins,
                        SshPmAddNameserverCB callback,
                        void *context)
{
#ifdef SSHDIST_UTIL_DNS_RESOLVER
    SshDNSResolver resolver;
    int i;

    resolver = ssh_name_server_resolver();
    if (resolver != NULL)
    {
        for (i = 0; i < num_dns; i++)
          ssh_dns_resolver_safety_belt_add(resolver, 1, &(dns[i]));
    }
#endif /* SSHDIST_UTIL_DNS_RESOLVER */
















    ssh_net_add_name_server_unix(num_dns, dns,
                                 callback, context);

}

void
ssh_pm_remove_name_servers(int32_t num_dns,
                           SshIpAddr dns,
                           int32_t num_wins,
                           SshIpAddr wins,
                           SshPmRemoveNameserverCB callback,
                           void *context)
{















    ssh_net_remove_name_server_unix(callback, context);

}
