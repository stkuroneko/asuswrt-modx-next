#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
//#include <sys/stat.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <ctype.h>

#define PROTOCOL "HTTP/1.0"

#include <rtconfig.h>

#ifdef RTCONFIG_FBWIFI
#define PROTOCOL_FBWIFI "HTTP/1.1"
#define SERVER_PORT 8084
#else
#define SERVER_PORT 80
#endif

#define SERVER_NAME "httpd"
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"

#ifndef ISXDIGIT
# define ISXDIGIT(x) (isxdigit((int) ((unsigned char)x)))
#endif

#include <curl/curl.h>
#include <curl/easy.h>

#include "bcmnvram_f.h"
#include <bcmnvram.h>	//2008.08 magic

int http_port=SERVER_PORT;

/* Const vars */
const int int_1 = 1;

/* Globals. */
static FILE *conn_fp;
char host_name[128];
char url[128];
char guestuser_cookie[64] = "\0";
char guestuser_redirectmac[64] = "\0";

typedef FILE * webs_t;
/* A multi-family sockaddr. */
typedef union {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
} usockaddr;

#include "queue.h"
#define MAX_CONN_ACCEPT 64
#define MAX_CONN_TIMEOUT 60

typedef struct conn_item {
        TAILQ_ENTRY(conn_item) entry;
        int fd;
        usockaddr usa;
} conn_item_t;

typedef struct conn_list {
        TAILQ_HEAD(, conn_item) head;
        int count;
} conn_list_t;

unsigned int getpeerip(webs_t wp){
        int fd, ret;
        struct sockaddr peer;
        socklen_t peerlen = sizeof(struct sockaddr);
        struct sockaddr_in *sa;

        fd = fileno((FILE *)wp);
        ret = getpeername(fd, (struct sockaddr *)&peer, &peerlen);
        sa = (struct sockaddr_in *)&peer;

        if (!ret){
//		csprintf("peer: %x\n", sa->sin_addr.s_addr);
                return (unsigned int)sa->sin_addr.s_addr;
        }
        else{
                //csprintf("error: %d %d \n", ret, errno);
                return 0;
        }
}

static void
send_headers( int status, char* title, char* extra_header, char* mime_type )
    {
    time_t now;
    char timebuf[100];

    (void) fprintf( conn_fp, "%s %d %s\r\n", PROTOCOL, status, title );
    (void) fprintf( conn_fp, "Server: %s\r\n", SERVER_NAME );
    now = time( (time_t*) 0 );
    (void) strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &now ) );
    (void) fprintf( conn_fp, "Date: %s\r\n", timebuf );
    if ( extra_header != (char*) 0 )
        (void) fprintf( conn_fp, "%s\r\n", extra_header );
    if ( mime_type != (char*) 0 )
        (void) fprintf( conn_fp, "Content-Type: %s\r\n", mime_type );

    (void) fprintf( conn_fp, "Connection: close\r\n" );
    (void) fprintf( conn_fp, "\r\n" );
    }

static void
send_error( int status, char* title, char* extra_header, char* text )
{
        send_headers( status, title, extra_header, "text/html" );
        (void) fprintf( conn_fp, "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\n<BODY BGCOLOR=\"#cc9999\"><H4>%d %s</H4>\n", status, title, status, title );
        (void) fprintf( conn_fp, "%s\n", text );
        (void) fprintf( conn_fp, "</BODY></HTML>\n" );
        (void) fflush( conn_fp );
}

void sethost(char *host)
{
        char *cp;

        if(!host) return;

        strcpy(host_name, host);

        cp = host_name;
        for ( cp = cp + 9; *cp && *cp != '\r' && *cp != '\n'; cp++ );
        *cp = '\0';
}

static int
        initialize_listen_socket( usockaddr* usaP )
{
    int listen_fd;

    memset( usaP, 0, sizeof(usockaddr) );
    usaP->sa.sa_family = AF_INET;
    usaP->sa_in.sin_addr.s_addr = htonl( INADDR_ANY );
    usaP->sa_in.sin_port = htons( http_port );

    listen_fd = socket( usaP->sa.sa_family, SOCK_STREAM, 0 );
    if ( listen_fd < 0 )
    {
        perror( "socket" );
        return -1;
    }
    (void) fcntl( listen_fd, F_SETFD, FD_CLOEXEC );
    if ( setsockopt( listen_fd, SOL_SOCKET, SO_REUSEADDR, &int_1, sizeof(int_1) ) < 0 )
    {
        close(listen_fd);	// 1104 chk
        perror( "setsockopt" );
        return -1;
    }
    if ( bind( listen_fd, &usaP->sa, sizeof(struct sockaddr_in) ) < 0 )
    {
        close(listen_fd);	// 1104 chk
        perror( "bind" );
        return -1;
    }
    if ( listen( listen_fd, 1024 ) < 0 )
    {
        close(listen_fd);	// 1104 chk
        perror( "listen" );
        return -1;
    }
    return listen_fd;
}

#ifdef RTCONFIG_FBWIFI
static void
send_fbwifi_headers( int status, char* title,  char* mime_type, char* location, char* cookie, char* continue_cookie)
{

    time_t now;
    char timebuf[100];

    (void) fprintf( conn_fp, "%s %d %s\r\n", PROTOCOL_FBWIFI, status, "Found" );
    (void) fprintf( conn_fp, "Server: %s\r\n", SERVER_NAME );

    //(void) fprintf( conn_fp, "Date: %s\r\n", timebuf );
    printf("Location :%s\n",location);
    (void) fprintf( conn_fp, "Location: %s\r\n", location );

    if(cookie)
    {
        now = time( (time_t*) 0 ) + 12*3600;

        (void) strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &now ) );
        printf("timebuf=%s\n",timebuf);
        (void) fprintf( conn_fp, "Set-Cookie: c_%s=%s; Expires=%s\r\n", continue_cookie ,cookie,timebuf);
    }
    if ( mime_type != (char*) 0 )
        (void) fprintf( conn_fp, "Content-Type: %s\r\n", mime_type );

    (void) fprintf( conn_fp, "Connection: close\r\n" );
    (void) fprintf( conn_fp, "\r\n" );
}

static void
send_captive_portal( int status, char* title,  char* text, char* location, char* cookie, char* continue_cookie)
{
    send_fbwifi_headers( status, title, "text/html", location, cookie, continue_cookie);
    //(void) fprintf( conn_fp, "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\n<BODY BGCOLOR=\"#cc9999\"><H4>%d %s</H4>\n", status, title, status, title );
    (void) fprintf( conn_fp, "<HTML><HEAD><TITLE>Redirecting to %s</TITLE></HEAD>\n<BODY>If you are not redirected within 5 seconds, please <a href=\"%s\">click here</a>.\n", text,location);
    //(void) fprintf( conn_fp, "%s\n", text );
    (void) fprintf( conn_fp, "</BODY></HTML>\n" );
    (void) fflush( conn_fp );
}

static void
send_page_fbwifi( int status, char* title, char* extra_header, char* text ){
    send_headers( status, title, extra_header, "text/html" );
    (void) fprintf( conn_fp, "%s\n", text );
    (void) fflush( conn_fp );
}

char fb_cookie[128] = "\0";
char fb_token[64]="\0";
char fb_original[64] = "\0";

void set_continue_cookie(char *host,char *mac)
{
    fprintf(stderr,"host:%s,mac:%s\n",host,mac);

    unsigned char *in;
    char *out;
    int len = strlen(host)+strlen(mac)+16;
    in = malloc(len);
    memset(in, 0, len);
    sprintf(in,"%s||http://%s",mac,host);
    
    out = md5_hash(in);
    tr_delete(out);
    tr_replace(out);
    printf("apply: %s\n", out);
    memset(guestuser_cookie, 0, 64);
    sprintf(guestuser_cookie,"%s",out);

    free(in);
#if 0
    char *fb_gid = nvram_safe_get("wl0.1_fbwifi_id");
    char *fb_secret = nvram_safe_get("wl0.1_fbwifi_secret");
#else
    char *fb_gid = nvram_safe_get("fbwifi_id");
    char *fb_secret = nvram_safe_get("fbwifi_secret");
#endif
    char *lan_ip = nvram_safe_get("lan_ipaddr");
    char *redirect_mac;
    
    len = strlen(fb_gid) + strlen(lan_ip) + strlen(out) + 128;
    redirect_mac = malloc(len);
    memset(redirect_mac, 0, len);
    sprintf(redirect_mac,"%s||http://%s:8084/fbwifi/auth.asp?c=%s",fb_gid,lan_ip,out);
    printf("redirect_mac: %s\n", redirect_mac);
    
    free(out);out = NULL;
    out = oauth_sign_hmac_sha256(redirect_mac,fb_secret);
    tr_delete(out);
    tr_replace(out);
    printf("out: %s\n", out);
    memset(guestuser_redirectmac, 0, 64);
    sprintf(guestuser_redirectmac,"%s",out);
    free(redirect_mac);
    free(out);
}

void
continue_broser_cookie(char *host)
{
    unsigned int ip;
    char ip_str[16];
    struct in_addr now_ip_addr;
    const int MAX = 80;
    const int VALUELEN = 18;
    char buffer[MAX], values[6][VALUELEN];
    char client_mac[16];

    ip = getpeerip(conn_fp);

    now_ip_addr.s_addr = ip;
    memset(ip_str, 0, 16);
    strcpy(ip_str, inet_ntoa(now_ip_addr));

    FILE *fp = fopen("/proc/net/arp", "r");
    if (fp){
        memset(buffer, 0, MAX);
        memset(values, 0, 6*VALUELEN);

        while (fgets(buffer, MAX, fp)){
            if (strstr(buffer, "br0") && !strstr(buffer, "00:00:00:00:00:00")){
                if (sscanf(buffer, "%s%s%s%s%s%s", values[0], values[1], values[2], values[3], values[4], values[5]) == 6){
                    if (!strcmp(values[0], ip_str)){
                        break;
                    }
                }

                memset(values, 0, 6*VALUELEN);
            }

            memset(buffer, 0, MAX);
        }

        fclose(fp);
    }
    printf("apply: %s %s %s\n", ip_str, host,values[3]);
    strcpy(client_mac, values[3]);
    //fbwifi_forwad(host,client_mac);
    set_continue_cookie(host,client_mac);
}

static char*
fbwifi_auth_cgi(char *token, char *guest_cookie)
{
        printf("token: %s,cookie: %s\n", token,guest_cookie);

        unsigned int ip;
        char ip_str[16];
        struct in_addr now_ip_addr;
        const int MAX = 80;
        const int VALUELEN = 18;
        char buffer[MAX], values[6][VALUELEN];
        char client_mac[16];

        ip = getpeerip(conn_fp);

        now_ip_addr.s_addr = ip;
        memset(ip_str, 0, 16);
        strcpy(ip_str, inet_ntoa(now_ip_addr));

        FILE *fp = fopen("/proc/net/arp", "r");
        if (fp){
                memset(buffer, 0, MAX);
                memset(values, 0, 6*VALUELEN);

                while (fgets(buffer, MAX, fp)){
                        if (strstr(buffer, "br0") && !strstr(buffer, "00:00:00:00:00:00")){
                                if (sscanf(buffer, "%s%s%s%s%s%s", values[0], values[1], values[2], values[3], values[4], values[5]) == 6){
                                        if (!strcmp(values[0], ip_str)){
                                                break;
                                        }
                                }

                                memset(values, 0, 6*VALUELEN);
                        }

                        memset(buffer, 0, MAX);
                }

                fclose(fp);
        }

        printf("token: %s,ip: %s,mac: %s\n", token,ip_str,values[3]);
        char *out = fbwifi_auth(ip_str,values[3],token,guest_cookie);
        //free(out);
        printf("captive_portal fbwifi_auth_cgi end\n");
        return out;

}

void
        url_init(char *query)
{
    int len, nel;
    char *q, *name, *value;
    /* Parse into individualassignments */
    q = query;
    len = strlen(query);
    nel = 1;
    while (strsep(&q, "&"))
        nel++;
    for (q = query; q< (query + len);) {
        value = name = q;
        /* Skip to next assignment */
        for (q += strlen(q); q < (query +len) && !*q; q++);
        /* Assign variable */
        name = strsep(&value,"=");
        if(strcmp(name,"c")==0)
            strcpy(fb_cookie,value);
        else if(strcmp(name,"token")==0)
            strcpy(fb_token,value);

    }
    printf("CGI[value] :%s %s \n", fb_cookie,fb_token);
}

void
        cookie_init(char *query,char *cookie)
{
    int len, nel;
    char *q, *name, *value;
    /* Parse into individualassignments */
    q = query;
    len = strlen(query);
    nel = 1;
    while (strsep(&q, "; "))
        nel++;
    for (q = query; q< (query + len);) {
        value = name = q;
        /* Skip to next assignment */
        for (q += strlen(q); q < (query +len) && !*q; q++);
        /* Assign variable */
        name = strsep(&value,"=");
        printf("name = %s\n",name);
        if(strcmp(name,cookie)==0)
        {
            strcpy(fb_original,value);
            break;
        }
    }
    printf("cookie[value] :%s  \n", fb_original);
}

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
#endif

int send_request(char *tokens,char *fb_gid,char *fb_secret)
{
    CURL *curl;
    CURLcode res;
    FILE *fp;
    fp=fopen("/tmp/fbwifi/fb_wifi_check_token.txt","w");

    /*curl --data "name=Router-Lobby-01" --data "vendor_key=h24a2Ed1VuTIJytQ_V6jNtqFmfZYyJNB5bG1fBbbqsY" --data "hw_version=1.0" --data "sw_version=2.0.0.5" https://graph.facebook.com/wifiauth*/

    int len = strlen(fb_secret) + 20;
    char *data=(char *)malloc(len);
    memset(data,0,len);
    sprintf(data,"secret=%s",fb_secret);

    len = strlen(fb_gid) + strlen("https://graph.facebook.com//wifiauth/")+strlen(tokens) + 1;
    char *url = (char *)malloc(len);
    memset(url,0,len);
    sprintf(url,"https://graph.facebook.com/%s/wifiauth/%s",fb_gid,tokens);
    printf("\nsend_request data:%s,url:%s\n",data,url);
    curl=curl_easy_init();

    if(curl){
        curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl,CURLOPT_URL,url);

        curl_easy_setopt(curl,CURLOPT_POSTFIELDS,data);
        //curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0);
        curl_easy_setopt(curl,CURLOPT_VERBOSE,1);
        curl_easy_setopt(curl,CURLOPT_TIMEOUT,90);
        curl_easy_setopt(curl,CURLOPT_WRITEDATA,fp);
        //curl_easy_setopt(curl,CURLOPT_WRITEHEADER,fp_hd);
        res=curl_easy_perform(curl);

        curl_easy_cleanup(curl);
        fclose(fp);
        free(data);
        free(url);
        return res;
    }
}

int fbwifi_ckeck_token(char *tokens)
{
	int check_result=0;
	char *fb_gid = nvram_safe_get("fbwifi_id");
        char *fb_secret = nvram_safe_get("fbwifi_secret");
        int res;
        res = send_request(tokens,fb_gid,fb_secret);
	if(res==0){
		FILE *fp;
		char temp[80];
		char *p;

		if (fp=fopen("/tmp/fbwifi/fb_wifi_check_token.txt", "r"))
		{
			if (fgets(temp,80,fp)!=NULL)
			{
				if (p=strstr(temp, "true"))
				{
					check_result=1;
				}
				else{
					check_result=0;
				}
			}
			fclose(fp);
		}
	
	}
	return check_result;
}

static void
        handle_request(void)
{
    printf("handle_request\n");
    char line[10000], *cur;
    char *method, *path, *protocol, *authorization, *boundary ;
#ifdef RTCONFIG_FBWIFI
    char *fb_cookie_full = NULL;
    char *user_agent = NULL;
#endif
    char *cp;
    char *file;
    int len;
    int cl = 0;

    /* Initialize the request variables. */
    authorization = boundary = NULL;
    host_name[0] = 0;
    bzero( line, sizeof line );

    /* Parse the first line of the request. */
    if ( fgets( line, sizeof(line), conn_fp ) == (char*) 0 ) {
        send_error( 400, "Bad Request", (char*) 0, "No request found." );
        return;
    }

    method = path = line;
    strsep(&path, " ");
    //while (*path == ' ') path++;
    while (path && *path == ' ') path++;	// oleg patch
    protocol = path;
    strsep(&protocol, " ");
    //while (*protocol == ' ') protocol++;
    while (protocol && *protocol == ' ') protocol++;    // oleg pat
    cp = protocol;
    strsep(&cp, " ");
    if ( !method || !path || !protocol ) {
        send_error( 400, "Bad Request", (char*) 0, "Can't parse request." );
        return;
    }
    cur = protocol + strlen(protocol) + 1;

    /* Parse the rest of the request headers. */
    while ( fgets( cur, line + sizeof(line) - cur, conn_fp ) != (char*) 0 )
    {
        if ( strcmp( cur, "\n" ) == 0 || strcmp( cur, "\r\n" ) == 0 ) {
            break;
        }
        else if ( strncasecmp( cur, "Authorization:", 14 ) == 0 )
        {
            cp = &cur[14];
            cp += strspn( cp, " \t" );
            authorization = cp;
            cur = cp + strlen(cp) + 1;
        }
        else if ( strncasecmp( cur, "Host:", 5 ) == 0 )
        {
            cp = &cur[5];
            cp += strspn( cp, " \t" );
            sethost(cp);
            cur = cp + strlen(cp) + 1;
        }
#ifdef RTCONFIG_FBWIFI
        else if ( strncasecmp( cur, "Cookie:", 7 ) == 0 )
        {
            cp = &cur[7];
            cp += strspn( cp, " \t" );
            fb_cookie_full = cp;
            cur = cp + strlen(cp) + 1;
        }
        else if ( strncasecmp( cur, "User-Agent:", 11 ) == 0 )
        {
            cp = &cur[11];
            cp += strspn( cp, " \t" );
            user_agent = cp;
            cur = cp + strlen(cp) + 1;
        }
#endif
        else if (strncasecmp( cur, "Content-Length:", 15 ) == 0) {
            cp = &cur[15];
            cp += strspn( cp, " \t" );
            cl = strtoul( cp, NULL, 0 );
        }
        else if ((cp = strstr( cur, "boundary=" ))) {
            boundary = &cp[9];
            for ( cp = cp + 9; *cp && *cp != '\r' && *cp != '\n'; cp++ );
            *cp = '\0';
            cur = ++cp;
        }
    }

    if ( strcasecmp( method, "get" ) != 0 && strcasecmp(method, "post") != 0 && strcasecmp(method, "head") != 0 ) {
        send_error( 501, "Not Implemented", (char*) 0, "That method is not implemented." );
        return;
    }

    if ( path[0] != '/' ) {
        send_error( 400, "Bad Request", (char*) 0, "Bad filename." );
        return;
    }
    file = &(path[1]);
    len = strlen( file );
    if ( file[0] == '/' || strcmp( file, ".." ) == 0 || strncmp( file, "../", 3 ) == 0 || strstr( file, "/../" ) != (char*) 0 || strcmp( &(file[len-3]), "/.." ) == 0 ) {
        send_error( 400, "Bad Request", (char*) 0, "Illegal filename." );
        return;
    }
#ifdef RTCONFIG_FBWIFI
    // disable iOS popup window. Zero 2014.07.24
    if ( user_agent != NULL && strncasecmp( user_agent, "CaptiveNetworkSupport", 21 ) == 0 )
    {
        //send_error( 400, "Bad Request", (char*) 0, "Illegal filename." );
        char inviteCode[256];
        snprintf(inviteCode, sizeof(inviteCode), "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n<HTML>\n<HEAD>\n\t<TITLE>Success</TITLE>\n</HEAD>\n<BODY>\nSuccess\n</BODY>\n</HTML>\n");
        send_page_fbwifi( 200, "OK", (char*) 0, inviteCode);
        return;
    }
    // disable Android popup window. Zero 2014.07.24
    if ( user_agent != NULL && strncasecmp( user_agent, "Dalvik", 6 ) == 0 )
    {
        //send_error( 400, "Bad Request", (char*) 0, "Illegal filename." );
        char inviteCode[256];
        snprintf(inviteCode, sizeof(inviteCode), "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n<HTML>\n<HEAD>\n\t<TITLE>Success</TITLE>\n</HEAD>\n<BODY>\nSuccess\n</BODY>\n</HTML>\n");
        send_page_fbwifi( 200, "OK", (char*) 0, inviteCode);
        return;
    }

    int con_type = 0;
    char original[64] = "\0";
    char *auth_redirect_mac = NULL;
#endif
    //	if (file[0] == '\0' || file[len-1] == '/')
    //        {
    //            //file = "index.asp";
    //            con_type = 0;
    //        }


    printf("httpd url: %s file: %s\n", url, file);

#ifdef RTCONFIG_FBWIFI
    if(file[0] != '\0')
    {
        if(!strncmp(file,"fbwifi/forward",strlen("fbwifi/forward")))
        {
            char *p = strstr(file,"fbwifi/forward.asp?u=");
            p += strlen("fbwifi/forward.asp?u=");
            strcpy(original,p);

            printf("original=%s\n",original);

            //continue_broser_cookie(original);

            con_type = 1;

        }
        else if(!strncmp(file,"fbwifi/auth",strlen("fbwifi/auth")))
        {
            char *p = strchr(file,'?');
            p++;
            url_init(p);

		int token_check_result;
		
		token_check_result= fbwifi_ckeck_token(fb_token);
		//printf("\ncaptive_portal token_check_result=%d\n",token_check_result);
		if(token_check_result==1){

		auth_redirect_mac = fbwifi_auth_cgi(fb_token,fb_cookie);

		con_type = 2;
		}
		else{
			con_type = 0;
		}
        }
        else if(!strncmp(file,"fbwifi/continue",strlen("fbwifi/continue")))
        {
            char *p = strchr(file,'?');
            p++;
            url_init(p);

            con_type = 3;
        }
        else
            con_type = 0;
    }
    else
        con_type = 0;

    char location[512] = "\0";

    printf("con_type = %d\n",con_type);
    switch (con_type) {
    case 0:
        {
            //char* lan_ip= nvram_get("lan_ipaddr");
		char fullURL[128] = "\0";
		sprintf(fullURL,"%s%s%s","http://",host_name,"/");
		printf("fulURL:%s\n", fullURL);
		char *url_encode = oauth_url_escape(fullURL);

		memset(host_name, 0, sizeof(host_name));
		strncpy(host_name, url_encode, strlen(url_encode));
		printf("host_name :%s\n", host_name);

            sprintf(location,"%s%s%s%s","http://",nvram_get("lan_ipaddr"),":8084/fbwifi/forward.asp?u=",host_name);

            send_captive_portal(302,"Redirecting to Gateway","Gateway",location, NULL, NULL);
            break;
        }
    case 1:
        {
            char *server_url = "https://www.facebook.com/wifiauth/login/?gw_id=";
            char redirect_url[128] = "\0";

            continue_broser_cookie(original);
            sprintf(redirect_url,"%s%s%s%s","http://",nvram_get("lan_ipaddr"),":8084/fbwifi/auth.asp?c=", guestuser_cookie);
            //encodeURIComponent(redirect_url)
            char *redirect_url_encode = oauth_url_escape(redirect_url);

            printf("redirect_url=%s\n",redirect_url_encode);
            sprintf(location,"%s%s%s%s%s%s",server_url,nvram_get("fbwifi_id"),"&redirect_url=",redirect_url_encode,"&redirect_mac=", guestuser_redirectmac);
            free(redirect_url_encode);
            printf("location=%s,original=%s\n",location,original);

            send_captive_portal(302,"Redirecting to Facebook","Facebook",location,original, guestuser_cookie);
            break;
        }
    case 2:
        {
            char *server_url = "https://www.facebook.com/wifiauth/portal/?gw_id=";
            char redirect_url[128] = "\0";
            sprintf(redirect_url,"%s%s%s%s","http://",nvram_get("lan_ipaddr"),":8084/fbwifi/continue.asp?c=",fb_cookie);
            //encodeURIComponent(redirect_url)
            char *redirect_url_encode = oauth_url_escape(redirect_url);
            sprintf(location,"%s%s%s%s%s%s%s%s",server_url,nvram_get("fbwifi_id"),"&token=",fb_token,"&redirect_url=",redirect_url_encode,"&redirect_mac=",auth_redirect_mac);
            free(redirect_url_encode);
            printf("location=%s\n",location);

            send_captive_portal(302,"Redirecting to Facebook","Facebook",location,NULL, NULL);
            break;
        }
    case 3:
        {
            char cookie_name[218] = "\0";
            sprintf(cookie_name,"c_%s",fb_cookie);

            printf("fb_cookie_full=%s\n",fb_cookie_full);

            if(fb_cookie_full)
            {
                char *tmp_original = malloc(strlen(fb_cookie_full)+1);
                memset(tmp_original,0,strlen(fb_cookie_full)+1);
                sprintf(tmp_original,"%s",fb_cookie_full);

                cookie_init(tmp_original,cookie_name);

                //_dprintf("fb_original=%s,len=%d\n",fb_original,strlen(fb_original));

                //_dprintf("fb_original=%c\n",fb_original[strlen(fb_original)-1]);

                //_dprintf("fb_original=%c\n",fb_original[strlen(fb_original)]);

                //_dprintf("fb_original=%c\n",fb_original[strlen(fb_original)-2]);

                if(fb_original[strlen(fb_original)-2] == '\r')
                {
                    //_dprintf("111\n");
                    fb_original[strlen(fb_original)-2] = '\0';
                }

                if(fb_original[strlen(fb_original)-2] == '\n')
                {
                    //_dprintf("222\n");
                    fb_original[strlen(fb_original)-2] = '\0';
                }

                printf("fb_original=%s,len=%d\n",fb_original,strlen(fb_original));

                char funny_original[128] = "\0";
		char *url_decode = oauth_url_unescape(fb_original, NULL);
		printf("url_decode:%s\n", url_decode);
		sprintf(funny_original,"%s",url_decode);   
                send_captive_portal(302,"Redirecting to original",funny_original,funny_original,NULL, NULL);

                free(tmp_original);
            }
            else
                send_captive_portal(302,"Redirecting to original","https://www.facebook.com","https://www.facebook.com",NULL, NULL);

            break;
        }
    default:
        {
            break;
        }


    }

    return;
#endif
}

int main(int argc, char **argv)
{
    usockaddr usa;
    int listen_fd;
    socklen_t sz = sizeof(usa);
    fd_set active_rfds;
    conn_list_t pool;

    /* Initialize listen socket */
    if ((listen_fd = initialize_listen_socket(&usa)) < 2) {
            fprintf(stderr, "can't bind to any address\n" );
            exit(errno);
    }

    /* Init connection pool */
    FD_ZERO(&active_rfds);
    TAILQ_INIT(&pool.head);
    pool.count = 0;

    /* Loop forever handling requests */
    for (;;) {
            int max_fd, count;
            struct timeval tv;
            fd_set rfds;
            conn_item_t *item, *next;

            memcpy(&rfds, &active_rfds, sizeof(rfds));
            if (pool.count < MAX_CONN_ACCEPT) {
                    FD_SET(listen_fd, &rfds);
                    max_fd = listen_fd;
            } else  max_fd = -1;
            TAILQ_FOREACH(item, &pool.head, entry)
                    max_fd = (item->fd > max_fd) ? item->fd : max_fd;

            /* Wait for new connection or incoming request */
            tv.tv_sec = MAX_CONN_TIMEOUT;
            tv.tv_usec = 0;
            while ((count = select(max_fd + 1, &rfds, NULL, NULL, &tv)) < 0 && errno == EINTR)
                    continue;
            if (count < 0) {
                    perror("select");
                    return errno;
            }

            /* Check and accept new connection */
            if (count && FD_ISSET(listen_fd, &rfds)) {
                    item = malloc(sizeof(*item));
                    if (item == NULL) {
                            perror("malloc");
                            return errno;
                    }
                    while ((item->fd = accept(listen_fd, &item->usa.sa, &sz)) < 0 && errno == EINTR)
                            continue;
                    if (item->fd < 0) {
                            perror("accept");
                            free(item);
                            continue;
                    }

                    /* Set the KEEPALIVE option to cull dead connections */
                    setsockopt(item->fd, SOL_SOCKET, SO_KEEPALIVE, &int_1, sizeof(int_1));

                    /* Add to active connections */
                    FD_SET(item->fd, &active_rfds);
                    TAILQ_INSERT_TAIL(&pool.head, item, entry);
                    pool.count++;

                    /* Continue waiting over again */
                    continue;
            }

            /* Check and process pending or expired requests */
            TAILQ_FOREACH_SAFE(item, &pool.head, entry, next) {
                    if (count && !FD_ISSET(item->fd, &rfds))
                            continue;

                    /* Delete from active connections */
                    FD_CLR(item->fd, &active_rfds);
                    TAILQ_REMOVE(&pool.head, item, entry);
                    pool.count--;

                    /* Process request if any */
                    if (count) {
                            if (!(conn_fp = fdopen(item->fd, "r+"))) {
                                    perror("fdopen");
                                    goto skip;
                            }
                                    handle_request();

                            fflush(conn_fp);

                            shutdown(item->fd, 2), item->fd = -1;
                            fclose(conn_fp);

                    skip:
                            /* Skip the rest of */
                            if (--count == 0)
                                    next = NULL;

                    }

                    /* Close timed out and/or still alive */
                    if (item->fd >= 0) {
                            shutdown(item->fd, 2);
                            close(item->fd);
                    }

                    free(item);
            }
    }

    shutdown(listen_fd, 2);
    close(listen_fd);

    return 0;
}
