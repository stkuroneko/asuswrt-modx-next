/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for casting between unsigned and signed character strings.
*/

#include "sshincludes.h"


/* Variants of the C library string functions that take unsigned character
   strings as input. */
int ssh_strlen(const char *str)
{
    return strlen(str);
}

#if !defined (KERNEL) && !defined(_KERNEL)
char *ssh_strncpy(char *str1,
                            const char *str2,
                            size_t len)
{
    return (char *)strncpy((char *)str1, (const char *)str2, len);
}

int ssh_strcmp(const char *str1, const char *str2)
{
    return strcmp((const char *)str1, (const char *)str2);
}

int ssh_strncmp(const char *str1, const char *str2,
                 size_t len)
{
    return strncmp((const char *)str1, (const char *)str2, len);
}

char *ssh_strcat(char *str1,
                           const char *str2)
{
    return (char *)strcat((char *)str1, (const char *)str2);
}

char *ssh_strchr(const char *str, int c)
{
    return (char *)strchr((const char *)str, c);
}

int ssh_strcasecmp(const char *str1, const char *str2)
{
    return strcasecmp((const char *)str1, (const char *)str2);
}

int ssh_strncasecmp(const char *str1, const char *str2,
                    size_t n)
{
    return strncasecmp((const char *)str1, (const char *)str2, n);
}

int ssh_atoi(const char *str)
{
    return atoi((const char *) str);
}

long ssh_atol(const char *str)
{
    return atol((const char *) str);
}

int ssh_strtol(const char *nptr, char **endptr, int base)
{
    return strtol((const char *) nptr, (char **) endptr, base);
}

int ssh_strtoul(const char *nptr, char **endptr, int base)
{
    return strtoul((const char *) nptr, (char **) endptr, base);
}

char *ssh_strcpy(char *dest, const char *src)
{
    return strcpy(dest, src);
}

#else /* !KERNEL && !_KERNEL */


char *ssh_strcpy(char *dest, const char *src)
{
    do
    {
        *dest = *src;
        ++dest;
    }
    while (*src++ != 0);

    return dest;
}


char *ssh_strncpy(char *dest, const char *src, size_t n)
{
    while (n > 0 && *src != 0)
    {
        *dest = *src;

        ++dest;
        ++src;
        --n;
    }

    while (n > 0)
    {
        *dest = 0;
        ++dest;
        --n;
    }

    return dest;
}

#endif /* KERNEL || _KERNEL */
