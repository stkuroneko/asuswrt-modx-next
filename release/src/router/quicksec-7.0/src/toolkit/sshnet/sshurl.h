/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   URL and HTTP POST data encode and decode.
*/

#ifndef SSHURL_H_INCLUDED
#define SSHURL_H_INCLUDED

typedef enum {
  SSH_URL_OK,
  /* No space available to complete operation. */
  SSH_URL_NO_MEMORY,
  /* Query does not contain requested entry. */
  SSH_URL_NO_SUCH_OBJECT,
  /* Invalid URL format. */
  SSH_URL_INVALID_ENCODING
} SshUrlError;

/* Query container has the following properties:
   - it retains orders of entries on enumeration.
   - individual entries within query are accessible via their name. */

typedef struct SshUrlQueryRec *SshUrlQuery;

/* Allocate a query (needed on applications performing URL
   construction themselves.  */
SshUrlQuery ssh_url_query_allocate(void);

/* Free a query allocated by application or received from the library. */
void ssh_url_query_free(SshUrlQuery query);

/* Query entry container has the following properties:
   - Other questions with the same key can be accessed from the entry. */
typedef struct SshUrlEntryRec *SshUrlEntry;

/* Create entry from key and value. Both key and value may be NULL
   pointers. Input values are copied from application memory.

   Return values: Pointer to an URL query entry, or NULL, if memory
   allocation failed. */
SshUrlEntry
ssh_url_entry_create(const char *key, size_t key_len,
                     const char *value, size_t data_len);

/* Get key value from given URL query entry. Length of key is filled
   into 'len' argument, if it is not a NULL pointer.

   Return value: Pointer to key value within the given entry or NULL,
   if the entry does not contain key.  The pointer returned belongs to
   the 'entry' container and must not be freed by the application. */
const char *
ssh_url_entry_key(SshUrlEntry entry, size_t *len);

/* Get data value from given URL query entry. Length of value is filled
   into 'len' argument, if it is not a NULL pointer.

   Return value: Pointer to data value within the given entry or NULL,
   if the entry does not contain data.  The pointer returned belongs
   to the 'entry' container and must not be freed by the
   application. */
const char *
ssh_url_entry_value(SshUrlEntry entry, size_t *len);

/* Destroy a query entry that is not part of a query. Entries
   belonging to a query are destroyed when the query is freed. */
void ssh_url_entry_destroy(SshUrlEntry entry);

/* Parse GET data. Decode URL escaped character sequences. */
SshUrlError
ssh_url_parse_get(const char *url,
                  char **scheme,
                  char **authority,
                  char **path,
                  SshUrlQuery *queries,
                   char **fragment,
                  bool relaxed);

/* Authority handling. User info management is left for
   application -> [[userinfo "@"] host [":" port]. If the
   host partition is given as [IPV6] address format then
   return it in that same format (i.e. keep the '[' and
   ']'). */
SshUrlError
ssh_url_parse_authority(const char *authority,
                        char **username, char **password,
                        char **host, char **port);

SshUrlError
ssh_url_construct_authority(const char *username,
                            const char *password,
                            const char *host,
                            const char *port,
                            char **authority);

/* Construct URL get from scheme, authority, path, queries and fragment, and
   fills properly encoded URL into 'url'.

   Return value: SSH_URL_OK if url encoding was successful, or some of
   the URL error values. 'url' will be set to NULL in case of error
   return. */
SshUrlError
ssh_url_construct_get(const char *scheme,
                      const char *authority,
                      const char *path,
                      const SshUrlQuery query,
                      const char *fragment,
                      char **url);

/* Parse POST data. Decode URL escaped character sequences. */
SshUrlError
ssh_url_parse_post(const char *data, SshUrlQuery *queries);

/* Construct post data. URL encode entries. */
SshUrlError
ssh_url_construct_post(SshUrlQuery queries, unsigned char **data);

/* Enumerate entries within the query. The entries are returned in
   oder they were at the url, post data, or inserted into query. */
SshUrlEntry
ssh_url_query_enumerate_start(SshUrlQuery query);
SshUrlEntry
ssh_url_query_enumerate_next(SshUrlQuery query, SshUrlEntry current);

/* Insert a entry into the tail of the query. */
SshUrlError
ssh_url_query_entry_insert(SshUrlQuery query, SshUrlEntry entry);

/* Remove the entry from the query. This removes only the exact
   entry entry, not other with the same key. The entry pointer
   given must originate from within the query. */
SshUrlError
ssh_url_query_entry_delete(SshUrlQuery query, SshUrlEntry entry);

/* Get the entry with given key from query. */
SshUrlEntry
ssh_url_query_get_entry(SshUrlQuery query,
                        const char *name, size_t name_len);

/* Get the next entry from query containing the same key the
   entry given contains. */
SshUrlEntry
ssh_url_query_get_next_same_entry(SshUrlQuery query,
                                  SshUrlEntry entry);

/* Perform URL encoding of unsafe characters on data. Return newly
   allocated memory buffer and fills its size to 'output_len', if it
   is a non null pointer. */
char *
ssh_url_data_encode(const char *data, size_t data_len,
                    size_t *output_len);

/* Perform URL decoding of unsafe characters on data. Return newly
   allocated memory buffer and fills its size to 'output_len', if it
   is a non null pointer. */
char *
ssh_url_data_decode(const char *data, size_t data_len,
                    size_t *output_len);

/*****************************************************************************
 * OLD API convenience functions for parsing GET URI In principle this
 * API is subject of removal, and thus it is not documented here. */

bool
ssh_url_parse(const char *url, char **scheme,
              char **host, char **port,
              char **user, char **pass,
              char **path);

bool
ssh_url_parse_and_decode(const char *url, char **scheme,
                         char **host, char **port,
                         char **user, char **pass,
                         char **path);

bool
ssh_url_parse_relaxed(const char *url, char **scheme,
                      char **host, char **port,
                      char **user, char **pass,
                      char **path);

bool
ssh_url_parse_and_decode_relaxed(const char *url,
                                 char **scheme, char **host,
                                 char **port, char **user,
                                 char **pass, char **path);
#endif /* SSHURL_H_INCLUDED */
