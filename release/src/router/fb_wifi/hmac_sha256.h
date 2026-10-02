#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define getb(type) (type*)malloc(sizeof(type))
#define NORMALSIZE 512
#define my_free(x)  free(x);x=NULL;

char *oauth_encode_base64(int size, const unsigned char *src);
int oauth_decode_base64(unsigned char *dest, const char *src);
char *oauth_url_escape(const char *string);
char *oauth_url_unescape(const char *string, size_t *olen);
char *oauth_sign_hmac_sha1 (const char *m, const char *k);
char *oauth_gen_nonce();
char *oauth_sign_hmac_sha256 (const char *m, const char *k);


char *oauth_sign_plaintext (const char *m, const char *k);
char *my_str_malloc(size_t len);

