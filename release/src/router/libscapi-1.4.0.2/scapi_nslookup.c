/******************************************************************************

  Copyright (c) 2012, 2014, 2015
  Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/



/* 
 ** =============================================================================
 **   FILE NAME        : nslookup.c
 **   PROJECT          : 
 **   DATE             : 02-Aug-2013
 **   AUTHOR           : 
 **   DESCRIPTION      : This file contains nslookup APIs 
 ** ============================================================================
 */


#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <resolv.h>
#include<strings.h>
#include <net/if.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include<sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ltq_api_include.h>

#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define ENABLE_FEATURE_CLEAN_UP 0

#ifdef CONFIG_FEATURE_IPV6
#define ENABLE_FEATURE_IPV6
#define IF_FEATURE_IPV6(...) __VA_ARGS__
#else
#define IF_NOT_FEATURE_IPV6
#endif

typedef unsigned short  sa_family_t;

static void scapi_set_nport_d(len_and_sockaddr_d *lsa, unsigned port)
{
	if (lsa->u.sa.sa_family == AF_INET6) {
		lsa->u.sin6.sin6_port = port;
		return;
	}
	if (lsa->u.sa.sa_family == AF_INET) {
		lsa->u.sin.sin_port = port;
		return;
	}
}



static char* scapi_sprintf(char *format, ...)
{
	va_list p;
	int r = 0;
	char *buf;

	buf = malloc(128);

	va_start(p, format);
	vsnprintf(buf, 128, format, p);
	va_end(p);

	if (r < 0)
		LOGF_LOG_ERROR("Scapi_sprintf error");

	return buf;
}

static char* scapi_sockaddr2str_d(struct sockaddr *sa, int flags)
{
	char host[128];
	char host_ip[128];
	char serv[16];
	int rc;
	socklen_t salen;

	if (sa->sa_family == AF_UNIX)
	{
		struct sockaddr_un *sun = (struct sockaddr_un *)sa;
		return scapi_sprintf("local:%.*s", (int) sizeof(sun->sun_path), sun->sun_path);
	}

	salen = LSA_SIZEOF_SA_D;
	if (sa->sa_family == AF_INET)
		salen = sizeof(struct sockaddr_in);
	if (sa->sa_family == AF_INET6)
		salen = sizeof(struct sockaddr_in6);
	rc = getnameinfo(sa, salen, host, sizeof(host), serv, sizeof(serv), flags);
	if (!rc)
		if (sa->sa_family == AF_INET6)
		{
			if (strchr(host, ':')) /* host name not resolved*/
				return scapi_sprintf("%s", host);
		}
	return scapi_sprintf("%s", host);

	if(sa->sa_family == AF_INET)
	{
		inet_ntop(AF_INET, (char *)host, host_ip, sizeof(host_ip));
		return scapi_sprintf("%s", host_ip);
	}

	return scapi_sprintf("%s", host);

}


static int32 scapi_str2sockaddr_d(char *host, int port, sa_family_t af, int ai_flags, len_and_sockaddr_d *r)
{

	int rc, iRet = 1;
	struct addrinfo *result = NULL;
	struct addrinfo *used_res;
	char *org_host = host; /* only for error msg */
	char *cp;
	struct addrinfo hint;

	r = NULL;

	/* parsing host:addr */
	if(af == AF_INET6 && host[0] == '[')
	{
		/* parsing [xx]:nn */
		host++;
		cp = strchr(host, ']');
		if (!cp || (cp[1] != ':' && cp[1] != '\0'))
		{
			/* Improper:should be [xx]:nn or [xx] */
			printf("bad address '%s'", org_host);
			return UGW_FAILURE;
		}
	}
	else
	{
		cp = strrchr(host, ':');
		if(af == AF_INET6 && strchr(host, ':') != cp)
		{
			/* Only 1 ':' allower. ::7 not allower*/
			cp = NULL; /* it's not a port spec */
		}
	}
	if (cp)
	{ /* points to ":" or "]:" */
		int sz = cp - host + 1;

		host = strncpy(alloca(sz), host, sz);
		if (af == AF_INET6 && *cp != ':')
		{
			cp++; /* skip ']' */
			if (*cp == '\0') /* [xx] without port */
				goto skip;
		}
		cp++; /* skip ':' */
skip: ;
	}
	if(af != AF_INET6)
	{
		struct in_addr in4;
		if (inet_aton(host, &in4) != 0)
		{
			r = malloc(LSA_LEN_SIZE_D + sizeof(struct sockaddr_in));
			if(r == NULL)
			{
				iRet = 0;
				goto ret;
			}
			r->len = sizeof(struct sockaddr_in);
			r->u.sa.sa_family = AF_INET;
			r->u.sin.sin_addr = in4;
			goto set_port;
		}
	}
	/* If not asked specifically for IPv4,
	 * check whether this is a numeric IPv6 */
	if (af != AF_INET) {
		struct in6_addr in6;
		if (inet_pton(AF_INET6, host, &in6) > 0)
		{
			r = malloc(LSA_LEN_SIZE_D + sizeof(struct sockaddr_in6));
			if(r == NULL)
			{
				iRet = 0;
				goto ret;
			}
			r->len = sizeof(struct sockaddr_in6);
			r->u.sa.sa_family = AF_INET6;
			r->u.sin6.sin6_addr = in6;
			goto set_port;
		}
	}


	memset(&hint, 0 , sizeof(hint));
	hint.ai_family = af;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_flags = 0;
	rc = getaddrinfo(host, NULL, &hint, &result);
	if (rc || !result)
	{
		printf("bad address '%s'", org_host);
		goto ret;
	}
	used_res = result;
	while (1) {
		if (used_res->ai_family == AF_INET)
			break;
		used_res = used_res->ai_next;
		if (!used_res) {
			used_res = result;
			break;
		}
	}
	r = malloc(LSA_LEN_SIZE_D + used_res->ai_addrlen);
	if(r == NULL)
	{
		iRet = 0;
		goto ret;
	}
	r->len = used_res->ai_addrlen;
	memcpy(&r->u.sa, used_res->ai_addr, used_res->ai_addrlen);

set_port:
	scapi_set_nport_d(r, htons(port));
ret:
	freeaddrinfo(result);
	return iRet;
}

static int scapi_host_print(char *hostname, char *header, char *ipaddr)
{
	int rc;
	struct addrinfo hint, *result = NULL;

	memset(&hint, 0 , sizeof(hint));

	hint.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo(hostname, NULL, &hint, &result);

	if (!rc)
	{
		struct addrinfo *cur = result;
		unsigned cnt = 0;

		while (cur)
		{
			char *dotted;//, *revhost;

			dotted = (char *)scapi_sockaddr2str_d(cur->ai_addr, 0);
			if(dotted != NULL)
				strcpy(ipaddr, dotted);

			cnt++;


			if (ENABLE_FEATURE_CLEAN_UP)
				free(dotted);
			cur = cur->ai_next;
			if(dotted)  free(dotted);
		}
	}
	else
		if (ENABLE_FEATURE_CLEAN_UP)
			freeaddrinfo(result);

	if(result) freeaddrinfo(result);
	return (rc != 0);
}



static void scapi_print_server(void)
{
	char *server;
	struct sockaddr *sa;
	char address[256] = { 0 };

	sa = (struct sockaddr*)_res._u._ext.nsaddrs[0];
	if (!sa)
		sa = (struct sockaddr*)&_res.nsaddr_list[0];

	server = scapi_sockaddr2str_d(sa, 0);

	scapi_host_print(server, "Server:", address);
	if (ENABLE_FEATURE_CLEAN_UP)
		free(server);

	if(server) free(server);
	putchar('\n');
}



static void scapi_default_dns_set(char *server)
{
	len_and_sockaddr_d lsa;
	int iRet = 0, port;

#ifdef IF_FEATURE_IPV6
	sa_family_t af = AF_INET6;
#endif

#ifdef IF_NOT_FEATURE_IPV6
	sa_family_t af = AF_INET;
#endif

	port = 53;
	iRet = scapi_str2sockaddr_d(server, port, af, AF_UNSPEC, &lsa);
	if(iRet != UGW_FAILURE)
	{
		if (lsa.u.sa.sa_family == AF_INET)
		{
			_res.nscount = 1;
			/* struct copy */
			_res.nsaddr_list[0] = lsa.u.sin;
		}
#ifdef ENABLE_FEATURE_IPV6
		if (lsa.u.sa.sa_family == AF_INET6)
		{
			_res._u._ext.nscount = 1;
			_res._u._ext.nsaddrs[0] = &lsa.u.sin6;
		}
#endif
	}
}

int scapi_nslookup(NSLOOKUP_DIAG_D * pxNSLookupQuery, NSLookupResp_D * pxNSLookupResp, RESULT_D *pxResult)
{

	int32 iloop = 0 , *hostname_flag = NULL, *dnssserver_flag = NULL;
	int32 i = 0, j = 0, k = 0, success_count = 0;

	struct timeval tv;
	struct tm *lt=NULL;
	time_t currtime;
	char buff[30], address[256] = { 0 };
	int hr,min,sec;
	long int t1=0,t2;
	int nRet = UGW_SUCCESS;

	if ((pxNSLookupQuery->hostname == NULL))
		exit(EXIT_FAILURE);

	iloop = pxNSLookupQuery->num_repetitions;

	hostname_flag = (int *)calloc(1,iloop*sizeof(int));
	if(hostname_flag == NULL)
	{
		return UGW_FAILURE;
	}

	dnssserver_flag = (int *)calloc(1,iloop*sizeof(int));
	if(dnssserver_flag == NULL)
	{
		free(hostname_flag);
		return UGW_FAILURE;
	}

	pxNSLookupQuery->result_num_entries = 0;

	for(i = 0; i < iloop; i++)
	{


		/* initialise DNS struct for default and explicit name server */
		res_init();


		if (pxNSLookupQuery->dnsserver)
			scapi_default_dns_set(pxNSLookupQuery->dnsserver);

		gettimeofday(&tv , NULL);
		currtime = tv.tv_sec;
		lt = localtime(&currtime);

		if(lt == NULL)
		{
			nRet = UGW_FAILURE;
			goto finish;
		}
 
		strftime(buff,30,"%T." , lt);
		sscanf(buff , "%d:%d:%d." , &hr , &min , &sec);
		t1 = (hr*60*60*1000) + (min*60*1000) +(sec*1000) + (tv.tv_usec /1000);

		scapi_print_server();

		gettimeofday(&tv , NULL);
		currtime = tv.tv_sec;
		lt = localtime(&currtime);

		if(lt == NULL)
		{
			nRet = UGW_FAILURE;
			goto finish;
		}
		strftime(buff,30,"%T." , lt);
		sscanf(buff , "%d:%d:%d." , &hr , &min , &sec);
		t2 = (hr*60*60*1000) + (min*60*1000)+(sec*1000) + (tv.tv_usec/1000);
		hostname_flag[i] = 1;

		scapi_host_print(pxNSLookupQuery->hostname, "Name:", address);

		if(address != NULL)
			hostname_flag[i] = 0;

		if(hostname_flag[i] == 1)
		{
			strcpy(pxResult[i].status, "Error_HostNameNotResolved");
			strcpy(pxResult[i].anstype , "None");
			pxResult[i].resp_time = 0;
			pxNSLookupQuery->result_num_entries += 1;
		}
		else
		{
			success_count += 1;
			strcpy(pxResult[i].status , "Success");
			strncpy(pxResult[i].dnsserver_ip, pxNSLookupQuery->dnsserver, MAX_IP_ADDR_LEN-1);
			strcpy(pxResult[i].hostname_ret, pxNSLookupQuery->hostname);
			pxResult[i].resp_time = t2 -t1 ; //TBD
			strcpy(pxResult[i].ipaddresses ,address);
			strcpy(pxResult[i].anstype , "NonAuthoritative");
			pxNSLookupQuery->result_num_entries += 1;
		}
	}
	strcpy(pxNSLookupResp->caDiagState,"Error_Other");
	for( j = 0 ; j < pxNSLookupQuery->num_repetitions ; j++ ){
		if(hostname_flag[j] == 0){
			strcpy(pxNSLookupResp->caDiagState,"Error_DNSServerNotResolved");
			for( k = 0 ; k < pxNSLookupQuery->num_repetitions ; k++ )
				if(dnssserver_flag[k] == 0){
					strcpy(pxNSLookupResp->caDiagState,"None");
					break;
				}
			break;
		}
	}

	pxNSLookupResp->iResultNumberOfSuccess = success_count;

	if(pxResult != NULL)
		pxNSLookupResp->pxResult = pxResult;

	if(strcmp(pxNSLookupResp->caDiagState,"None")==0)
		strcpy(pxNSLookupResp->caDiagState,"Complete");

finish:
	if(hostname_flag) free(hostname_flag);
	if(dnssserver_flag) free(dnssserver_flag);

	return nRet;
}                         
