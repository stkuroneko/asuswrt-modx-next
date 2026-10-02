/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP address parsing related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"




#define SSH_DEBUG_MODULE "SshInetParse"

/* Parses an IP address from the string to the internal representation. */

static bool ssh_ipaddr_ipv4_parse(unsigned char *data,
                                     const char *str)
{
    int i, value;
    bool bracket = false;

    if (*str == '[')
    {
        str++;
        bracket = true;
    }

    for (i = 0; i < 4; i++)
    {
        if (i != 0)
        {
            if (!*str)
            {
                switch (i)
                {
                  case 1:
                    /* Single zero means 0.0.0.0.
                       Other single digit address is invalid. */
                    if (data[0] == 0)
                    {
                        data[1] = data[2] = data[3] = 0;
                        return true;
                    }
                    return false;

                  case 2:
                    /* 1.2 -> 1.0.0.2 */
                    data[3] = data[1];
                    data[1] = data[2] = 0;
                    return true;

                  case 3:
                    /* 1.2.3 -> 1.2.0.3 */
                    data[3] = data[2];
                    data[2] = 0;
                    return true;
                }
            }
            else if (*str == '.' && *(str + 1) != '.')
            {
                str++;
            }
            else
            {
                return false;
            }
        }
        for (value = 0; *str >= '0' && *str <= '9'; str++)
        {
            value = 10 * value + *str - '0';
            if (value > 255)
              return false;
        }
        if (bracket && *str == ']')
        {
            str++;
            if (*str)
              return false;
            bracket = false;
        }

        if ((*str && *str != '.' && !(*str >= '0' && *str <= '9')) ||
            (!*str && i == 0))
            return false;

        data[i] = value;
    }

    if (bracket)
      return false;

    if (*str)
      return false;

    return true;
}

#if !defined(WITH_IPV6)
/* ARGSUSED0 */
static bool ssh_ipaddr_ipv6_parse(unsigned char *addr,
                                     const unsigned char *str)
{
    return false;
}
#else /* WITH_IPV6 */

#define h2i(CH) (((CH) >= '0' && (CH) <= '9') ? ((CH) - '0') : \
                  (((CH) >= 'a' && (CH) <= 'f') ? ((CH) - 'a' + 10) : \
                   (((CH) >= 'A' && (CH) <= 'F') ? ((CH) - 'A' + 10) : (-1))))

static bool ssh_ipaddr_ipv6_parse(unsigned char *addr,
                                     const char *str)
{
    const char *cp, *start, *next;
    int                 right, i;
    unsigned char       out_bytes[4];
    unsigned long       tmp, need_bytes, right_ptr, left_ptr;
    bool bracket = false;
    size_t len;

    if (addr)
    {
        /* Zero addr */
        memset(addr, 0, 16);
    }

    if (*str == '[')
    {
        str++;
        bracket = true;
    }

    /* Have we seen a "::" yet? */
    right = 0;
    left_ptr = 0;
    right_ptr = 16;

    start = cp = str;

    /* Look for next ':' delimiter */
    while (*start)
    {
        if ((cp = ssh_strchr(start, ':')) != NULL)
        {
            next = cp + 1;
        }
        else
        {
            cp = ssh_strchr(start, '\0');
            next = cp;
            /* This is last item, check if there is bracket if needed. */
            if (bracket)
            {
                cp--;
                if (next[-1] != ']')
                {
                    return false;
                }
                bracket = false;
            }
        }

        len = cp - start;

        if (len == 0)
        {
            if (*next != ':')
            {
                /* printf("ERROR: Empty element\n"); */
                return false;
            }
            need_bytes = 0;
        }

        /* ipv6 'x', 'xx', 'xxx' or 'xxxx' part? */
        else if (len <= 4)
        {
            for (tmp = i = 0; i < len; i++)
            {
                if (h2i(start[i]) == -1)
                {
                    /* printf("ERROR: Invalid character in address\n"); */
                    return false;
                }
                tmp = (tmp << 4) | h2i(start[i]);
            }

            out_bytes[0] = (unsigned char)((tmp >>  8) & 0xff);
            out_bytes[1] = (unsigned char)((tmp >>  0) & 0xff);

            need_bytes = 2;
        }
        else if (memchr(start, '.', len) != NULL && (len <= 15))
        {
            char buf[16];

            memcpy(buf, start, len);
            buf[len] = '\0';
            if (bracket && len > 0)
            {
                if (buf[len - 1] == ']')
                {
                    buf[len - 1] = '\0';
                }
                else
                {
                    return false;
                }
            }

            if (ssh_ipaddr_ipv4_parse(out_bytes, buf) == false)
              return false;

            need_bytes = 4;
        }

        else
        {
            /* printf("ERROR: Unrecognized address part\n"); */
            return false;
        }

        if ((right_ptr - left_ptr) < need_bytes)
        {
#if 0
            printf("ERROR: Not enough space in output address "
                   "(have %d, required %d)\n",
                   right_ptr - left_ptr, need_bytes);
#endif
            return false;
        }

        if (right)
        {
            if (addr)
            {
                memmove(addr + right_ptr - need_bytes,
                        addr + right_ptr,
                        16 - right_ptr);
                memcpy(addr + 16 - need_bytes, out_bytes, need_bytes);
            }
            right_ptr -= need_bytes;
        }
        else
        {
            if (addr)
              memcpy(addr + left_ptr, out_bytes, need_bytes);
            left_ptr += need_bytes;
        }

        if (*next == ':')
        {
            if (right)
            {
                /* printf("ERROR: Already seen '::'\n"); */
                return false;
            }

            right = 1;
            next++;
        }

        /* Move on to next iteration */
        start = next;
        if (bracket)
        {
            if (start[0] == ']' && start[1] == '\0')
            {
                bracket = false;
                break;
            }
        }
    }

    if (bracket)
      return false;

    if ((right_ptr - left_ptr) > 0 && !right)
    {
        /* printf("ERROR: %d unresolved address bytes\n",
           right_ptr - left_ptr); */
        return false;
    }

    return true;
}
#endif /* !WITH_IPV6 */

/* Determines whether the given string is a valid numeric IP address. */

bool ssh_inet_is_valid_ip_address(const char *address)
{
    unsigned char tmp[16];

    if (ssh_ipaddr_ipv4_parse(tmp, address) ||
        ssh_ipaddr_ipv6_parse(tmp, address))
      return true;
    return false;
}

bool ssh_ipaddr_parse(SshIpAddr ip, const char *str)
{
    char buf[64];
    const char *cp;

    /* Is the scope ID part given? */
    cp = ssh_strchr(str, '%');
    if (cp)
    {
        /* Yes it is.  Let's ignore it. */
        if (cp - str + 1 > sizeof(buf))
          /* This can not be a valid IP address since all decimal IP
             addresses fit into 64 bytes. */
          return false;

        memcpy(buf, str, cp - str);
        buf[cp - str] = '\0';
    }
    else
    {
        /* No it isn't.  Store the address into our buffer. */
        if (ssh_strlen(str) + 1 > sizeof(buf))
          /* This can not be a valid IP address since all decimal IP
             addresses fit into 64 bytes. */
          return false;

        ssh_strncpy(buf, str, sizeof(buf));
        /* Clear the scope id. */
#if defined(WITH_IPV6)
        SSH_IP6_SCOPE_ID(ip) = 0;
#endif /* WITH_IPV6 */
    }

    /* Try to parse it first as ipv4 address, then as ipv6 */
    if (ssh_ipaddr_ipv4_parse(ip->addr_data, buf))
    {
        ip->type = SSH_IP_TYPE_IPV4;
        ip->mask_len = 32;
        return true;
    }

#if defined(WITH_IPV6)
    if (ssh_ipaddr_ipv6_parse(ip->addr_data, buf))
    {
        ip->type = SSH_IP_TYPE_IPV6;
        ip->mask_len = 128;










        if (cp)
          return ssh_ipaddr_resolve_scope_id(&ip->scope_id, cp + 1);
        else
          return true;

    }
#endif /* WITH_IPV6 */

    SSH_IP_UNDEFINE(ip);
    return false;
}

/* ssh_ipaddr_parse_with_mask

   If mask == NULL, we expect that str is in format "a.b.c.d/masklen"
   instead. */

bool ssh_ipaddr_parse_with_mask(SshIpAddr ip, const char *str,
                                   const char *mask)
{
    char *dup, *cp;
    bool     ret;

    dup = NULL;
    ret = false;

    SSH_IP_UNDEFINE(ip);

    /* Clear the scope id. */
#if defined(WITH_IPV6)
    SSH_IP6_SCOPE_ID(ip) = 0;
#endif /* WITH_IPV6 */

    if (mask == NULL)
    {
        dup = ssh_strdup(str);
        if (!dup)
          return false;

        if ((cp = ssh_strchr(dup, '/')) == NULL)
        {
            ssh_free(dup);
            return false;
        }
        str = dup;
        mask = cp + 1;

        *cp = '\0';
    }

    /* Try to parse as ipv4 address */
    if (ssh_ipaddr_ipv4_parse(ip->addr_data, str) == true)
    {
        ip->type = SSH_IP_TYPE_IPV4;

        ret = false;

        /* x.x.x.x/y.y.y.y type netmask? Dang. Parse and count the bits. */
        if (ssh_strchr(mask, '.') != NULL)
        {
            SshIpAddrStruct mask_ip;

            if (ssh_ipaddr_ipv4_parse(mask_ip.addr_data, mask))
            {
                uint32_t mask_bits, mask_len;

                mask_bits = SSH_IP4_TO_INT(&mask_ip);
                mask_len = 0;

                while (mask_len < 32 && ((mask_bits >> 31) & 0x1))
                {
                    mask_bits <<= 1;
                    mask_len++;
                }

                ip->mask_len = mask_len;

                ret = true;
            }
        }
        else
        {
            ip->mask_len = ssh_atoi(mask);
            ret = true;
        }
    }
    else if (ssh_ipaddr_ipv6_parse(ip->addr_data, str) == true)
    {
        ip->type = SSH_IP_TYPE_IPV6;

        /* x:x:x:x:x:x:x:x type netmask? Dang. Parse and count the bits. */
        if (ssh_strchr(mask, ':') != NULL)
        {
            SshIpAddrStruct mask_ip;

            if (ssh_ipaddr_ipv6_parse(mask_ip.addr_data, mask))
            {
                uint32_t mask_bits = 0, mask_len, i;

                mask_len = 0;
                for (i = 0; i < 4; i++)
                {
                    if (i == 0)
                      mask_bits = SSH_IP6_WORD0_TO_INT(&mask_ip);
                    else if (i == 1)
                      mask_bits = SSH_IP6_WORD1_TO_INT(&mask_ip);
                    else if (i == 2)
                      mask_bits = SSH_IP6_WORD2_TO_INT(&mask_ip);
                    else if (i == 3)
                      mask_bits = SSH_IP6_WORD3_TO_INT(&mask_ip);
                    else
                      SSH_NOTREACHED;

                    if (mask_bits == 0xffffffff)
                    {
                        mask_len += 32;
                        continue;
                    }

                    while (mask_len < 128)
                    {
                        if (mask_bits & 0x80000000)
                          mask_len++;
                        else
                          goto done;

                        mask_bits <<= 1;
                    }
                }

              done:
                ip->mask_len = mask_len;
            }
        }
        else
        {
            ip->mask_len = ssh_atoi(mask);
        }

        ret = true;
    }

    if (dup != NULL)
      ssh_free(dup);

    return ret;
}

/* Parses an IP address with an optional IPv6 link-local address scope
   ID.  The addresses with a scope ID are given as `ADDR%SCOPEID'.  On
   success, the function returns a pointer to the scope ID part of the
   address in `scope_id_return'.  The value returned in
   `scope_id_return' will point into the original input string `str'.
   If the string `str' does not contain the scope ID part, the
   `scope_id_return' is set to NULL. */

bool ssh_ipaddr_parse_with_scope_id(SshIpAddr ip, const char *str,
                                       char **scope_id_return)
{
    char *cp;

    /* Is the scope ID part given? */
    cp = ssh_strchr(str, '%');
    if (cp)
    {
        /* Yes it was. */
        *scope_id_return = (cp + 1);
    }
    else
    {
        /* No it wasn't. */
        *scope_id_return = NULL;
#if defined(WITH_IPV6)
        memset(&ip->scope_id, 0, sizeof(ip->scope_id));
#endif /* WITH_IPV6 */
    }

    /* Parse the IP address part. This will fill up scope ID into 'ip' */
    return ssh_ipaddr_parse(ip, str);
}
