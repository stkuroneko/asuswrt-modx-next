/*
 * Project: udptunnel
 * File: socket.c
 *
 * Copyright (C) 2009 Daniel Meekins
 * Contact: dmeekins - gmail
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
//#include <string.h>
//#include <sys/types.h>

#ifndef WIN32
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif /* WIN32 */

#include <socket.h>
#include <common.h>

/*pjsip logging*/
#include <pj/log.h>
#if PJ_ANDROID==1
#include <j_log.h>
#define THIS_FILE "socket.c"
#include <errno.h>
#else
#define LOG_E(x, ...)
#endif

#define THIS_FILE "socket.c"

#ifdef _WIN32
#define s_addr  S_un.S_addr /* can be used for most tcp & ip code */
#endif

//int debug_level = NO_DEBUG;
int debug_level = DEBUG_LEVEL3;
//int debug_level = DEBUG_LEVEL2;
int ipver = SOCK_IPV4;

void print_hexdump(char *data, int len);

/* 
 * DEAN modified 
 * Allocates and returns a new socket structure.
 * host - string of host or address to listen on (can be NULL for servers)
 * port - string of port number or service (can be NULL for clients) 
 * rip  - string of address which the remote client should connect to. 
 * rport - string of port number which the remote client should connect to. 
 * ipver - SOCK_IPV4 or SOCK_IPV6
 * sock_type - SOCK_TYPE_TCP or SOCK_TYPE_UDP
 * is_serv - 1 if is a server socket to bind and listen on port, 0 if client
 * conn - call socket(), bind(), and listen() if is_serv, or connect()
 *        if not is_serv. Doesn't call these if conn is 0.
 * qos_priority - The QoS priority of this socket.
 * disable_flow_control - Disable flow control or not.
 * inst_id - The instance id of SDK.
 * call_id - The identity of tunnel.
 * client_id - The identity of session.
 */
int sock_create(socket_t** sock, char *host, char *port, char *rip, char *rport, int ipver, int sock_type,
                      int is_serv, int conn, uint8_t qos_priority, uint8_t disable_flow_control, 
					  uint16_t speed_limit, int inst_id, int call_id)
{
    //socket_t *sock = NULL;
    struct addrinfo hints;
    struct addrinfo *info = NULL;
    struct sockaddr *paddr;
    int ret;
    int error_code;
    *sock = NULL;
    
    (*sock) = (socket_t *)malloc(sizeof(**sock));
    if(!*sock)
        return -1;

	pj_memset(*sock, 0, sizeof(**sock));

    paddr = SOCK_PADDR(*sock);
    (*sock)->fd = -1;

    switch(sock_type)
    {
        case SOCK_TYPE_TCP:
            (*sock)->type = SOCK_STREAM;
            break;
        case SOCK_TYPE_UDP:
            (*sock)->type = SOCK_DGRAM;
            break;
        default:
            goto error;
    }

    /* If both host and port are null, then don't create any socket or
       address, but still set the AF. */
    if(host == NULL && port == NULL)
    {
        (*sock)->addr.ss_family = (ipver == SOCK_IPV6) ? AF_INET6 : AF_INET;
        goto done;
    }

    /* DEAN added*/
	(*sock)->lport = atoi(port);
   
	(*sock)->rport = 0;
    if (is_serv)
		(*sock)->rport = atoi(rport);

	if (rip)
		strcpy((*sock)->rip, rip);

	if (qos_priority > 99)
		(*sock)->qos_priority = (uint8_t)99;
	else
		(*sock)->qos_priority = (uint8_t)qos_priority;

	if (disable_flow_control > 1)
		(*sock)->disable_flow_control = (uint8_t)1;
	else
		(*sock)->disable_flow_control = (uint8_t)disable_flow_control;

	(*sock)->speed_limit = (uint16_t)speed_limit;

	(*sock)->inst_id = inst_id;
	(*sock)->call_id = call_id;
    (*sock)->client_id = -1;
	memset((*sock)->im_dest_deviceid, 0, sizeof((*sock)->im_dest_deviceid));
    
    /* Setup type of address to get */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (ipver == SOCK_IPV6) ? AF_INET6 : AF_INET;
    hints.ai_socktype = (*sock)->type;
    hints.ai_flags = is_serv ? AI_PASSIVE : 0;

    /* Get address from the machine */
    ret = getaddrinfo(host, port, &hints, &info);
	error_code = pj_get_native_netos_error();
	//PERROR_GOTO(THIS_FILE, ret != 0, "getaddrinfo", error, error_code);
	if (ret != 0) {
	    /*PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
		               "  [%d/%d/?] sock_create() Failed to call getaddrinfo(). err=[%d]", 
					   inst_id, call_id, error_code));*/
		PJ_LOG(1, (THIS_FILE, "  [%d/%d/?] sock_create() Failed to call getaddrinfo(). err=[%d], %s", 
			inst_id, call_id, ret, gai_strerror(ret)));
		goto error;
	}
    memcpy(paddr, info->ai_addr, info->ai_addrlen);
    (*sock)->addr_len = info->ai_addrlen;

    if(conn)
    {
		error_code = sock_connect(*sock, is_serv);
        if(error_code != 0)
            goto error;
    }

done:
	if (strcmp(port, "0") == 0)
		sprintf(port, "%d", (*sock)->lport);

    if(info)
        freeaddrinfo(info);
    
    return 0;
    
  error:
	if(*sock)
        sock_free(sock);
    if(info)
        freeaddrinfo(info);
    
    return error_code;
}

socket_t *sock_copy(socket_t *sock)
{
    socket_t *new_sock;

    new_sock = (socket_t *)malloc(sizeof(*sock));
    if(!new_sock)
        return NULL;

    memcpy(new_sock, sock, sizeof(*sock));

    return new_sock;
}

/*
 * If the socket is a server, start listening. If it's a client, connect to
 * to destination specified in sock_create(). Returns -1 on error or -2 if
 * the socket is already connected.
 */
int sock_connect(socket_t *sock, int is_serv)
{
    struct sockaddr *paddr;
    int ret, tr = 1, error_code;
    int sobuf_size = 0, flag_len;
    struct linger lin;
	char addr_str[MAX_IP_LEN];
	uint16_t port = 0;
    char *sock_type = (char *)(sock->type == SOCK_STREAM ? "TCP" : "UDP"); // Just for logs.

    if(sock->fd != -1)
        return -1;
        
    paddr = SOCK_PADDR(sock);
	pj_memset(addr_str, 0, sizeof(addr_str));
	if (paddr->sa_family == AF_INET)
		pj_inet_ntop(PJ_AF_INET, pj_sockaddr_get_addr(paddr), addr_str, sizeof(addr_str));
	else if (paddr->sa_family == AF_INET6)
		pj_inet_ntop(PJ_AF_INET6, pj_sockaddr_get_addr(paddr), addr_str, sizeof(addr_str));
	
	port = pj_sockaddr_get_port(paddr);
    
    /* Create socket file descriptor */
    sock->fd = socket(paddr->sa_family, sock->type, 0);
	error_code = pj_get_native_netos_error();
	//PERROR_GOTO(THIS_FILE, sock->fd < 0, "socket", error, error_code);
	if (sock->fd < 0)
		PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
		               "  [%d/%d/?] sock_connect() [%s] socket create for [127.0.0.1:%d] failed. err=[%d]", 
					   sock->inst_id, sock->call_id, sock_type, sock->lport, error_code));

    if(is_serv)
    {
		// DEAN Patch by author
        /* Kill "Address already in use" error message */
        ret = setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, (char *)&tr, sizeof(int));
		error_code = pj_get_native_netos_error();
		//PERROR_GOTO(THIS_FILE, ret != 0, "setsockopt", error, error_code);
		if (ret != 0)
			PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
			               "  [%d/%d/?] sock_connect() [%s] socket SO_REUSEADDR option set failed [%s:%d]. err=[%d]", 
			               sock->inst_id, sock->call_id, sock_type, addr_str, port, error_code));

        /* Bind socket to address and port */
        ret = bind(sock->fd, paddr, sock->addr_len);
		error_code = pj_get_native_netos_error();
		//PERROR_GOTO(THIS_FILE, ret != 0, "bind", error, error_code);
		if (ret != 0)
			PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
			               "  [%d/%d/?] sock_connect() [%s] socket bind to [%s:%d] failed. err=[%d]", 
			               sock->inst_id, sock->call_id, sock_type, addr_str, port, error_code));

		PJ_LOG(4, (THIS_FILE, "  [%d/%d/?] sock_connect() [%s] socket bound to [%s:%d].", 
			   sock->inst_id, sock->call_id, sock_type, addr_str, port));
        
        /* Start listening on the port if tcp */
        if(sock->type == SOCK_STREAM)
        {
            ret = listen(sock->fd, BACKLOG);
			error_code = pj_get_native_netos_error();
			//PERROR_GOTO(THIS_FILE, ret != 0, "listen", error, error_code);
			if (ret != 0)
				PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
				               "  [%d/%d/?] sock_connect() [%s] socket listen failed for [%s:%d]. err=[%d]", 
							   sock->inst_id, sock->call_id, sock_type, addr_str, port, error_code));

			if (sock->lport == 0) {
				struct sockaddr_in addr;
				socklen_t len = sizeof(addr);;
				ret = getsockname(sock->fd, (struct sockaddr *)&addr, &len);
				error_code = pj_get_native_netos_error();
				if (ret != 0)
					PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
					"  [%d/%d/?] sock_connect() [%s] getsockname failed for [%s:%d]. err=[%d]", 
					sock->inst_id, sock->call_id, sock_type, addr_str, port, error_code));

				sock->lport = ntohs(addr.sin_port);
			}
			PJ_LOG(4, (THIS_FILE, "  [%d/%d/?] sock_connect() [%s] socket for [%s:%d] is listening.", 
				       sock->inst_id, sock->call_id, sock_type, addr_str, port));
		}
    }
    else
    {
		if (sock->type == SOCK_DGRAM)
			return 0;

        /* Connect to the server if tcp */
		ret = connect(sock->fd, paddr, sock->addr_len);
		error_code = pj_get_native_netos_error();
		//PERROR_GOTO(THIS_FILE, ret != 0, "connect", error, error_code);
		if (ret != 0)
			PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
			               "  [%d/%d/%d] sock_connect() [%s] socket connect [%s:%d] failed. err=[%d]", 
			               sock->inst_id, sock->call_id, sock->client_id, sock_type, addr_str, sock->lport, error_code));

		PJ_LOG(4, (THIS_FILE, "  [%d/%d/%d] sock_connect() [%s] socket connected to [%s:%d].", 
			   sock->inst_id, sock->call_id, sock->client_id, sock_type, addr_str, sock->lport));
    }

    return ret;
    
  error:
    return error_code;
}

/*
 * Accept a new connection and return a newly allocated socket representing
 * the remote connection.
 */
socket_t *sock_accept(socket_t *serv_sock)
{
    socket_t *client;
    int error_code;
    char *sock_type = (char *)(serv_sock->type == SOCK_STREAM ? "TCP" : "UDP"); // Just for logs.
    
    client = (socket_t *)calloc(1, sizeof(*client));
	if(!client) {
		error_code = pj_get_native_netos_error();
		PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
		               "  [%d/%d/?] sock_accept() [%s] socket accept from [127.0.0.1:%d] failed on memory allocating. err=[%d]", 
		               serv_sock->inst_id, serv_sock->call_id, sock_type, serv_sock->lport, error_code));
	}

    client->type = serv_sock->type;
	client->qos_priority = serv_sock->qos_priority;
	client->disable_flow_control = serv_sock->disable_flow_control;
	client->speed_limit = serv_sock->speed_limit;
    client->addr_len = sizeof(struct sockaddr_storage);
    client->fd = accept(serv_sock->fd, SOCK_PADDR(client), &client->addr_len);

	// Check the fd is valid or not.
	if (SOCK_FD(client) < 0) {
		error_code = pj_get_native_netos_error();
		PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
			"  [%d/%d/?] sock_accept() [%s] socket accept from [127.0.0.1:%d] failed. err=[%d]", 
			serv_sock->inst_id, serv_sock->call_id, sock_type, serv_sock->lport, error_code));
	}

	client->lport = serv_sock->lport;
	client->rport = serv_sock->rport;
	client->inst_id = serv_sock->inst_id;
	client->call_id = serv_sock->call_id;
	client->client_id = serv_sock->client_id;
	memset(client->im_dest_deviceid, 0, sizeof(client->im_dest_deviceid));
	if (strlen(serv_sock->im_dest_deviceid) > 0)
		strcpy(client->im_dest_deviceid, serv_sock->im_dest_deviceid);
	client->im_timeout_sec = serv_sock->im_timeout_sec;
	strcpy(client->rip, serv_sock->rip);

	PJ_LOG(4, (THIS_FILE, "  [%d/%d/?] sock_accept() Got an incoming [%s] conneciton on [127.0.0.1:%d] for tunnel rport [%s:%d]", 
		client->inst_id, client->call_id, sock_type, client->lport, client->rip, client->rport));
        
    return client;
    
  error:
	if(client) {
        free(client);
	}

    return NULL;
}

/*
 * Closes the file descriptor for the socket.
 */
void sock_close(socket_t *s)
{
   if(s && s->fd != -1)
   {
	   char *sock_type = (char *)(s->type == SOCK_STREAM ? "TCP" : "UDP"); // Just for logs.
	   int fd = s->fd;
#ifdef WIN32
        closesocket(s->fd);
#else
        close(s->fd);
#endif
		s->fd = -1;
		PJ_LOG(4, (THIS_FILE, "  [%d/%d/%d] sock_close() [%s] socket [%d] for [127.0.0.1:%d] has been closed.", 
			s->inst_id, s->call_id, s->client_id, sock_type, fd, s->lport));
    }
}

/*
 * Frees the socket structure.
 */
void sock_free(socket_t **s)
{
	if (*s) {
		int inst_id = (*s)->inst_id;
		int call_id = (*s)->call_id;
		int client_id = (*s)->client_id;
		PJ_LOG(4, (THIS_FILE, "  [%d/%d/%d] sock is freeing.", 
			inst_id, call_id, client_id));

		free(*s);
		*s = NULL;

		PJ_LOG(4, (THIS_FILE, "  [%d/%d/%d] sock is freed.", 
			inst_id, call_id, client_id));
	}
}

/*
 * Returns non zero if IP addresses and ports are same, or 0 if not.
 */
int sock_addr_equal(socket_t *s1, socket_t *s2)
{
    if(s1->addr_len != s2->addr_len)
        return 0;
    
    return (sock_ipaddr_cmp(s1, s2) == 0) && (sock_port_cmp(s1, s2) == 0);
}

/*
 * Compares only the IP address of two sockets
 */
int sock_ipaddr_cmp(socket_t *s1, socket_t *s2)
{
    char *a1;
    char *a2;
    int len;
    
    if(s1->addr.ss_family != s2->addr.ss_family)
        return s1->addr.ss_family - s2->addr.ss_family; /* ? */

    switch(s1->addr.ss_family)
    {
        case AF_INET:
            a1 = (char *)(&SIN(&s1->addr)->sin_addr);
            a2 = (char *)(&SIN(&s2->addr)->sin_addr);
            len = 4; /* 32 bits */
            break;
            
        case AF_INET6:
            a1 = (char *)(&SIN6(&s1->addr)->sin6_addr);
            a2 = (char *)(&SIN6(&s2->addr)->sin6_addr);
            len = 16; /* 128 bits */
            break;

        default:
            return 0; /* ? */
    }

    return memcmp(a1, a2, len);
}

/*
 * Compares only the ports of two sockets
 */
int sock_port_cmp(socket_t *s1, socket_t *s2)
{
    uint16_t p1;
    uint16_t p2;

    if(s1->addr.ss_family != s2->addr.ss_family)
        return s1->addr.ss_family - s2->addr.ss_family; /* ? */
    
    switch(s1->addr.ss_family)
    {
        case AF_INET:
            p1 = ntohs(SIN(&s1->addr)->sin_port);
            p2 = ntohs(SIN(&s2->addr)->sin_port);
            break;
            
        case AF_INET6:
            p1 = ntohs(SIN6(&s1->addr)->sin6_port);
			p2 = ntohs(SIN6(&s2->addr)->sin6_port);
			break;
            
        default:
            return 0; /* ? */
	}

    return p1 - p2;
}

/*
 * Returns 1 if the address in the socket is 0.0.0.0 or ::, and 0 if not.
 */
int sock_isaddrany(socket_t *s)
{
    struct in6_addr zaddr = PJ_IN6ADDR_ANY_INIT;

    switch(s->addr.ss_family)
    {
        case AF_INET:
#if defined(NDEBUG) && defined(_WIN64)
			return (SIN(&s->addr)->sin_addr.S_un.S_addr== INADDR_ANY) ? 1 : 0;
#else
            return (SIN(&s->addr)->sin_addr.s_addr == INADDR_ANY) ? 1 : 0;
#endif

//#else
	//		return 0;
//#endif
        case AF_INET6:
            if(memcmp(&SIN6(&s->addr)->sin6_addr, &zaddr, sizeof(zaddr)) == 0)
                return 1;
            else
                return 0;

        default:
            return 1;
    }
}
/*
 * Gets the string representation of the IP address and port from addr. Will
 * store result in buf, which len must be at least INET6_ADDRLEN + 6. Returns a
 * pointer to buf. String will be in the form of "ip_address:port".
 */
#ifdef WIN32
char *sock_get_str(socket_t *s, char *buf, int len)
{
    DWORD plen = len;

	// DEAN modified
	/*wchar_t wtext[40];
	mbstowcs(wtext, buf, strlen(buf));
	LPWSTR ptr = wtext;*/
    
	if(WSAAddressToStringA(SOCK_PADDR(s), SOCK_LEN(s), NULL, buf, &plen) != 0)
        return NULL;

    return buf;
}
#else
char *sock_get_str(socket_t *s, char *buf, int len)
{
    void *src_addr;
    char addr_str[INET6_ADDRSTRLEN];
    uint16_t port;
    
    switch(s->addr.ss_family)
    {
        case AF_INET:
            src_addr = (void *)&SIN(&s->addr)->sin_addr;
            port = ntohs(SIN(&s->addr)->sin_port);
            break;

        case AF_INET6:
            src_addr = (void *)&SIN6(&s->addr)->sin6_addr;
            port = ntohs(SIN6(&s->addr)->sin6_port);
            break;
            
        default:
            return NULL;
    }

    if(inet_ntop(s->addr.ss_family, src_addr,
                 addr_str, sizeof(addr_str)) == NULL)
        return NULL;

    snprintf(buf, len, (s->addr.ss_family == AF_INET6) ? "[%s]:%hu" : "%s:%hu",
             addr_str, port);

    return buf;
}
#endif /*WIN32*/

/*
 * Gets the string representation of the IP address and puts it in buf. Will
 * return the pointer to buf or NULL if there was an error.
 */
#ifdef WIN32
char *sock_get_addrstr(socket_t *s, char *buf, int len)
{
    socket_t *copy = NULL;
    
    if((copy = sock_copy(s)) == NULL)
        return NULL;
    
    switch(copy->addr.ss_family)
    {
        case AF_INET:
            SIN(&copy->addr)->sin_port = 0;
            break;

        case AF_INET6:
            SIN6(&copy->addr)->sin6_port = 0;
            break;

        default:
            return NULL;
    }

    /* Calls to this will put the port in the string, so seting the port to 0
     * will just return the IP address. */
    if(sock_get_str(copy, buf, len) == NULL)
        goto error;

    free(copy);
    return buf;

  error:
	if(copy) {
		free(copy);
	}
    
    return NULL;
}
#else /*~WIN32*/
char *sock_get_addrstr(socket_t *s, char *buf, int len)
{
    void *src_addr;

    switch(s->addr.ss_family)
    {
        case AF_INET:
            src_addr = (void *)&SIN(&s->addr)->sin_addr;
            break;

        case AF_INET6:
            src_addr = (void *)&SIN6(&s->addr)->sin6_addr;
            break;
            
        default:
            return NULL;
    }

    if(inet_ntop(s->addr.ss_family, src_addr, buf, len) == NULL)
        return NULL;

    return buf;
}
#endif /*WIN32*/

/*
 * Returns the 16-bit port number in host byte order from the passed sockaddr.
 */
uint16_t sock_get_port(socket_t *s)
{
	if (s) {
		switch(s->addr.ss_family)
		{
			case AF_INET:
				return (uint16_t)ntohs(SIN(&s->addr)->sin_port);

			case AF_INET6:
				return (uint16_t)ntohs(SIN6(&s->addr)->sin6_port);
		}
	}

    return 0;
}

/*
 * Receives data from the socket. Calles recv() or recvfrom() depending on the
 * type of socket. Ignores the 'from' argument if type is for TCP, or puts
 * remove address in from socket for UDP. Reads up to len bytes and puts it in
 * data. Returns number of bytes sent, or 0 if remote host disconnected, or -1
 * on error.
 */
int sock_recv(socket_t *sock, socket_t *from, char *data, int len)
{
    int bytes_recv = 0;
    socket_t tmp;
    int error_code;
    char *sock_type = (char *)(sock->type == SOCK_STREAM ? "TCP" : "UDP"); // Just for logs.

    if (!sock)
        return -1;

    switch(sock->type)
    {
        case SOCK_STREAM:
            bytes_recv = recv(sock->fd, data, len, 0);
            break;

        case SOCK_DGRAM:
            if(!from)
                from = &tmp; /* In case caller wants to ignore from socket */
            from->fd = sock->fd;
            from->addr_len = sock->addr_len;
            bytes_recv = recvfrom(from->fd, data, len, 0,
									SOCK_PADDR(from), &SOCK_LEN(from));
			// DEAN, special case for retrieving source socket.
			if (bytes_recv == -1 && len == 0) // message too long.
				return 0;
			from->type = SOCK_DGRAM;

            break;
    }
    
	error_code = pj_get_native_netos_error();	

	if (sock->type == SOCK_STREAM) {
		//PERROR_GOTO(THIS_FILE, bytes_recv < 0, "recv", error, error_code);
		if (bytes_recv < 0)
			PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
			               "  [%d/%d/%d] sock_recv() [%s] Failed to receive data from [127.0.0.1:%d]. err=[%d]", 
						   sock->inst_id, sock->call_id, sock->client_id, sock_type, sock->lport, error_code));
	} else {
		//PERROR_GOTO(THIS_FILE, bytes_recv < 0, "recv", error, error_code);
		if (bytes_recv < 0)
			PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
			               "  [%d/%d/%d] sock_recv() [%s] Failed to receive data from [127.0.0.1:%d]. err=[%d]", 
						   sock->inst_id, sock->call_id, sock->client_id, sock_type, sock->lport, error_code));
	}
	//ERROR_GOTO(THIS_FILE, bytes_recv == 0, "disconnect", disconnect);
	if (bytes_recv == 0)
		PJ_PERROR_GOTO(1, disconnect, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
		               "  [%d/%d/%d] sock_recv() [%s] The connection of [127.0.0.1:%d] has been gracefully closed by remote peer. err=[%d]", 
					   sock->inst_id, sock->call_id, sock->client_id, sock_type, sock->lport, error_code));

    // DEAN modified
    //if(debug_level >= DEBUG_LEVEL3)
    //{
	PJ_LOG(5, (THIS_FILE, "  [%d/%d/%d] sock_recv() [%s] Received [%d] bytes data from [127.0.0.1:%d]",
               sock->inst_id, sock->call_id, sock->client_id, sock_type, bytes_recv, sock->lport));
    print_hexdump(data, bytes_recv);
    //}
    
    return bytes_recv;
    
  disconnect:
    return 0;
    
  error:
    return -1;
}

/*
 * Receives data from the socket. Calles recv() or recvfrom() depending on the
 * type of socket. Ignores the 'from' argument if type is for TCP, or puts
 * remove address in from socket for UDP. Reads up to len bytes and puts it in
 * data. Returns number of bytes sent, or 0 if remote host disconnected, or -1
 * on error.
 */
int sock_recv_whole_data(socket_t *sock, socket_t *from, char *data, int len)
{
	int ret;
	int recved_len = 0;
	int max_data_len = NATNL_IM_MAX_LEN;
	int num = 0;
	fd_set read_fds;
	struct timeval timeout;
	int retry_cnt = 0;
	int is_short_connection = 0;

#define HTTP_HEADER_CONNECTION_CLOSE "Connection: close"

	if (!sock)
		return -1;
	if (!data)
		return -2;

	memset(data, 0, len);
	do {
		ret = sock_recv(sock, from, (data + recved_len), (max_data_len - recved_len));
		PJ_LOG(4, (THIS_FILE, " [%d] sock_recv_whole_data() sock_recv() data=[%p], buff_size=[%d] ret=[%d]", 
			sock->inst_id, data + recved_len, max_data_len - recved_len, ret));

		// If the packet contains HTTP_HEADER_CONNECTION_CLOSE header, it represents the short connection.
		if (recved_len == 0 && strstr(data, HTTP_HEADER_CONNECTION_CLOSE) != NULL)
			is_short_connection = 1;

		if(ret < 0)
			return -3;
		if(ret == 0)
			return recved_len;

		recved_len += ret;

		PJ_LOG(4, (THIS_FILE, " [%d/%d] sock_recv_whole_data() Received data from [127.0.0.1:%d]. len=[%d]", 
			sock->inst_id, sock->call_id, sock->lport, recved_len));

select_retry:
		timeout.tv_sec = 0;
		timeout.tv_usec = 100;
		FD_ZERO(&read_fds);
		FD_SET(SOCK_FD(sock), &read_fds);
		num = select(SOCK_FD(sock)+1, &read_fds, NULL, NULL, &timeout);

		PJ_LOG(4, (THIS_FILE, " [%d/%d] sock_recv_whole_data() Received data from [127.0.0.1:%d]. select num=[%d]", 
			sock->inst_id, sock->call_id, sock->lport, num));

		// Only when the long connection need the limit of retry count.
		if (!is_short_connection && !num && retry_cnt < 60) {
			retry_cnt++;
			goto select_retry;
		}

	} while ((max_data_len - recved_len) > 0 && (num > 0 || is_short_connection));

	if (num > 0)
		return -4;
	else
		return recved_len;
}

/*
 * Sends len bytes in data to the socket connection. Returns number of bytes
 * sent, or 0 on disconnect, or -1 on error.
 */
int sock_send(socket_t *to, char *data, int len)
{
    int bytes_sent = 0;
    int ret, error_code; 
    char *sock_type = (char *)(to->type == SOCK_STREAM ? "TCP" : "UDP"); // Just for logs.

    if (!to)
        return -1;

    switch(to->type)
    {
        case SOCK_STREAM:
            while(bytes_sent < len)
            {
#if defined(WIN32) || defined(PJ_DARWINOS)
                ret = send(to->fd, data + bytes_sent, len - bytes_sent, 0); //DEAN modified
#else
                ret = send(to->fd, data + bytes_sent, len - bytes_sent, MSG_NOSIGNAL); //DEAN modified
#endif
				error_code = pj_get_native_netos_error();
				//PERROR_GOTO(THIS_FILE, ret < 0, "send", error, error_code);
				//ERROR_GOTO(THIS_FILE, ret == 0, "disconnected", disconnect);
				if (ret < 0)
					PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
					               "  [%d/%d/%d] sock_send() [%s] Failed to send data to [127.0.0.1:%d]. err=[%d]", 
								   to->inst_id, to->call_id, to->client_id, sock_type, to->lport, error_code));
				if (ret == 0)
					PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
					               "  [%d/%d/%d] sock_send() [%s] The connection of [127.0.0.1:%d] has been gracefully closed by remote peer. err=[%d]", 
					               to->inst_id, to->call_id, to->client_id, sock_type, to->lport, error_code));
                bytes_sent += ret;
            }
            break;

        case SOCK_DGRAM:
            ret = sendto(to->fd, data, len, 0,
                                SOCK_PADDR(to), to->addr_len);
			error_code = pj_get_native_netos_error();
			//PERROR_GOTO(THIS_FILE, bytes_sent < 0, "sendto", error, error_code);
			if (ret < 0)
				PJ_PERROR_GOTO(1, error, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
				               "  [%d/%d/%d] sock_send() [%s] Failed to send data to [127.0.0.1:%d]. err=[%d]", 
							   to->inst_id, to->call_id, to->client_id, sock_type, to->lport, error_code));
			bytes_sent += ret;
            break;

        default:
            return 0;
    }

    // DEAN modified
    //if(debug_level >= DEBUG_LEVEL3)
    //{
	PJ_LOG(5, (THIS_FILE, "  [%d/%d/%d] sock_send() [%s] Send [%d] bytes data to [127.0.0.1:%d]",
				to->inst_id, to->call_id, to->client_id, sock_type, bytes_sent, to->lport));
	print_hexdump(data, bytes_sent);
    //}

    return bytes_sent;

  disconnect:
    return 0;
    
  error:
    return -1;
}

/*
 * Releases the memory used by the socket.
 */
void socket_t_free(socket_t **s) {

    if(*s) {
        sock_close(*s);
        sock_free(s);
    }
}

/*
 * Checks validity of an IP address string based on the version
 */
int isipaddr(char *ip, int ipver)
{
    char addr[sizeof(struct in6_addr)];
    int len;
    int af_type;

    af_type = (ipver == SOCK_IPV6) ? AF_INET6 : AF_INET;
    len = sizeof(addr);
    
#ifdef WIN32
	// DEAN modified
	/*wchar_t wtext[40];
	mbstowcs(wtext, ip, strlen(ip));
	LPWSTR ptr = wtext;*/

    if(WSAStringToAddressA(ip, af_type, NULL, PADDR(addr), &len) == 0)
        return 1;
#else /*~WIN32*/    
    if(inet_pton(af_type, ip, addr) == 1)
        return 1;
#endif /*WIN32*/

    return 0;
}

/*
 * Debugging function to print a hexdump of data with ascii, for example:
 * 00000000  74 68 69 73 20 69 73 20  61 20 74 65 73 74 20 6d  this is  a test m
 * 00000010  65 73 73 61 67 65 2e 20  62 6c 61 68 2e 00        essage.  blah..
 */
void print_hexdump(char *data, int len)
{
    #if defined(DUMP_HEX) && DUMP_HEX == 1 //DEAN
    int line;
    int max_lines = (len / 16) + (len % 16 == 0 ? 0 : 1);
    int i;
    
    for(line = 0; line < max_lines; line++)
    {
        printf("%08x  ", line * 16);

        /* print hex */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
                printf("%02x ", (uint8_t)data[i]);
            else
                printf("   ");
        }
        printf(" ");
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
                printf("%02x ", (uint8_t)data[i]);
            else
                printf("   ");
        }

        printf(" ");
        
        /* print ascii */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
            {
                if(32 <= data[i] && data[i] <= 126)
                    printf("%c", data[i]);
                else
                    printf(".");
            }
            else
                printf(" ");
        }
        printf(" ");
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
            {
                if(32 <= data[i] && data[i] <= 126)
                    printf("%c", data[i]);
                else
                    printf(".");
            }
            else
                printf(" ");
        }

        printf("\n");
    }
    #endif
}

