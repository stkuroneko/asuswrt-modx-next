#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <math.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/stat.h>
#include<signal.h>
#include "hmac_sha256.h"

char *my_str_malloc(size_t len){

    //printf("len = %d\n",len);

    char *s;
    s = (char *)malloc(sizeof(char)*len);
    if(s == NULL)
    {
        printf("Out of memory.\n");
        exit(1);
    }

    memset(s,'\0',sizeof(char)*len);
    return s;
}

static void *xmalloc_fatal(size_t size) {
    if (size==0) return NULL;
    fprintf(stderr, "Out of memory.");
    exit(1);
}

void *xmalloc (size_t size) {
    void *ptr = malloc (size);
    if (ptr == NULL) return xmalloc_fatal(size);
    return ptr;
}

void *xcalloc (size_t nmemb, size_t size) {
    void *ptr = calloc (nmemb, size);
    if (ptr == NULL) return xmalloc_fatal(nmemb*size);
    return ptr;
}

void *xrealloc (void *ptr, size_t size) {
    void *p = realloc (ptr, size);
    if (p == NULL) return xmalloc_fatal(size);
    return p;
}

char *xstrdup (const char *s) {
    void *ptr = xmalloc(strlen(s)+1);
    strcpy (ptr, s);
    return (char*) ptr;
}

/**
 * Base64 encode one byte
 */
char oauth_b64_encode(unsigned char u) {
    if(u < 26)  return 'A'+u;
    if(u < 52)  return 'a'+(u-26);
    if(u < 62)  return '0'+(u-52);
    if(u == 62) return '+';
    return '/';
}

/**
 * Decode a single base64 character.
 */
unsigned char oauth_b64_decode(char c) {
    if(c >= 'A' && c <= 'Z') return(c - 'A');
    if(c >= 'a' && c <= 'z') return(c - 'a' + 26);
    if(c >= '0' && c <= '9') return(c - '0' + 52);
    if(c == '+')             return 62;
    return 63;
}

/**
 * Return TRUE if 'c' is a valid base64 character, otherwise FALSE
 */
int oauth_b64_is_base64(char c) {
    if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
       (c >= '0' && c <= '9') || (c == '+')             ||
       (c == '/')             || (c == '=')) {
        return 1;
    }
    return 0;
}

/**
 * Base64 encode and return size data in 'src'. The caller must free the
 * returned string.
 *
 * @param size The size of the data in src
 * @param src The data to be base64 encode
 * @return encoded string otherwise NULL
 */
char *oauth_encode_base64(int size, const unsigned char *src) {
    int i;
    char *out, *p;

    if(!src) return NULL;
    if(!size) size= strlen((char *)src);
    out= (char*) xcalloc(sizeof(char), size*4/3+4);
    p= out;

    for(i=0; i<size; i+=3) {
        unsigned char b1=0, b2=0, b3=0, b4=0, b5=0, b6=0, b7=0;
        b1= src[i];
        if(i+1<size) b2= src[i+1];
        if(i+2<size) b3= src[i+2];

        b4= b1>>2;
        b5= ((b1&0x3)<<4)|(b2>>4);
        b6= ((b2&0xf)<<2)|(b3>>6);
        b7= b3&0x3f;

        *p++= oauth_b64_encode(b4);
        *p++= oauth_b64_encode(b5);

        if(i+1<size) *p++= oauth_b64_encode(b6);
        else *p++= '=';

        if(i+2<size) *p++= oauth_b64_encode(b7);
        else *p++= '=';
    }
    return out;
}

/**
 * Decode the base64 encoded string 'src' into the memory pointed to by
 * 'dest'.
 *
 * @param dest Pointer to memory for holding the decoded string.
 * Must be large enough to receive the decoded string.
 * @param src A base64 encoded string.
 * @return the length of the decoded string if decode
 * succeeded otherwise 0.
 */
int oauth_decode_base64(unsigned char *dest, const char *src) {
    if(src && *src) {
        unsigned char *p= dest;
        int k, l= strlen(src)+1;
        unsigned char *buf= (unsigned char*) xcalloc(sizeof(unsigned char), l);

        /* Ignore non base64 chars as per the POSIX standard */
        for(k=0, l=0; src[k]; k++) {
            if(oauth_b64_is_base64(src[k])) {
                buf[l++]= src[k];
            }
        }

        for(k=0; k<l; k+=4) {
            char c1='A', c2='A', c3='A', c4='A';
            unsigned char b1=0, b2=0, b3=0, b4=0;
            c1= buf[k];

            if(k+1<l) c2= buf[k+1];
            if(k+2<l) c3= buf[k+2];
            if(k+3<l) c4= buf[k+3];

            b1= oauth_b64_decode(c1);
            b2= oauth_b64_decode(c2);
            b3= oauth_b64_decode(c3);
            b4= oauth_b64_decode(c4);

            *p++=((b1<<2)|(b2>>4) );

            if(c3 != '=') *p++=(((b2&0xf)<<4)|(b3>>2) );
            if(c4 != '=') *p++=(((b3&0x3)<<6)|b4 );
        }
        free(buf);
        dest[p-dest]='\0';
        return(p-dest);
    }
    return 0;
}




/**
 * Escape 'string' according to RFC3986 and
 * http://oauth.net/core/1.0/#encoding_parameters.
 *
 * @param string The data to be encoded
 * @return encoded string otherwise NULL
 * The caller must free the returned string.
 */
char *oauth_url_escape(const char *string) {
    size_t alloc, newlen;
    char *ns = NULL, *testing_ptr = NULL;
    unsigned char in;
    size_t strindex=0;
    size_t length;

    if (!string) return xstrdup("");

    alloc = strlen(string)+1;
    newlen = alloc;

    ns = (char*) xmalloc(alloc);

    length = alloc-1;
    while(length--) {
        in = *string;

        switch(in){
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
        case 'a': case 'b': case 'c': case 'd': case 'e':
        case 'f': case 'g': case 'h': case 'i': case 'j':
        case 'k': case 'l': case 'm': case 'n': case 'o':
        case 'p': case 'q': case 'r': case 's': case 't':
        case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
        case 'A': case 'B': case 'C': case 'D': case 'E':
        case 'F': case 'G': case 'H': case 'I': case 'J':
        case 'K': case 'L': case 'M': case 'N': case 'O':
        case 'P': case 'Q': case 'R': case 'S': case 'T':
        case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
        case '_': case '~': case '.': case '-':
            ns[strindex++]=in;
            break;
        default:
            newlen += 2; /* this'll become a %XX */
            if(newlen > alloc) {
                alloc *= 2;
                testing_ptr = (char*) xrealloc(ns, alloc);
                ns = testing_ptr;
            }
            snprintf(&ns[strindex], 4, "%%%02X", in);
            strindex+=3;
            break;
        }
        string++;
    }
    ns[strindex]=0;
    return ns;
}

#ifndef ISXDIGIT
# define ISXDIGIT(x) (isxdigit((int) ((unsigned char)x)))
#endif

/**
 * Parse RFC3986 encoded 'string' back to  unescaped version.
 *
 * @param string The data to be unescaped
 * @param olen unless NULL the length of the returned string is stored there.
 * @return decoded string or NULL
 * The caller must free the returned string.
 */
char *oauth_url_unescape(const char *string, size_t *olen) {
    size_t alloc, strindex=0;
    char *ns = NULL;
    unsigned char in;
    long hex;

    if (!string) return NULL;
    alloc = strlen(string)+1;
    ns = (char*) xmalloc(alloc);

    while(--alloc > 0) {
        in = *string;
        if(('%' == in) && ISXDIGIT(string[1]) && ISXDIGIT(string[2])) {
            char hexstr[3]; // '%XX'
            hexstr[0] = string[1];
            hexstr[1] = string[2];
            hexstr[2] = 0;
            hex = strtol(hexstr, NULL, 16);
            in = (unsigned char)hex; /* hex is always < 256 */
            string+=2;
            alloc-=2;
        }
        ns[strindex++] = in;
        string++;
    }
    ns[strindex]=0;
    if(olen) *olen = strindex;
    return ns;
}

/*   HMAC-SHA1 */
char *oauth_sign_hmac_sha1_raw (const char *m, const size_t ml, const char *k, const size_t kl) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int resultlen = 0;

    HMAC(EVP_sha1(), k, kl,
         (unsigned char*) m, ml,
         result, &resultlen);

    return(oauth_encode_base64(resultlen, result));
}

char *oauth_sign_hmac_sha1 (const char *m, const char *k) {
    return(oauth_sign_hmac_sha1_raw (m, strlen(m), k, strlen(k)));
}

/*   HMAC-SHA256 */
char *oauth_sign_hmac_sha256_raw (const char *m, const size_t ml, const char *k, const size_t kl) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int resultlen = 0;

    HMAC(EVP_sha256(), k, kl,
         (unsigned char*) m, ml,
         result, &resultlen);

    return(oauth_encode_base64(resultlen, result));
}

char *oauth_sign_hmac_sha256 (const char *m, const char *k) {
    return(oauth_sign_hmac_sha256_raw (m, strlen(m), k, strlen(k)));
}

/*   PLAINTEXT */
char *oauth_sign_plaintext (const char *m, const char *k) {
    return(oauth_url_escape(k));
}
