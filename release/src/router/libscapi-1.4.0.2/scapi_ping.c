/******************************************************************************

                         Copyright (c) 2012, 2014, 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/


/* 
** =============================================================================
**   FILE NAME        : ping_api.c
**   PROJECT          : 
**   DATE             : 02-Aug-2013
**   AUTHOR           : 
**   DESCRIPTION      : This file contains the ping/ping6 APIs 
** ============================================================================
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include<strings.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include "ltq_api_include.h"


static unsigned short checksum(void *b, int len);

enum {
        DEFDATALEN = 56,
        MAXIPLEN = 60,
        MAXICMPLEN = 76,
        MAXPACKET = 65468,
        PINGINTERVAL = 1, /* 1 second */
};


struct packet
{
    struct icmphdr hdr;
    char *msg;
};




/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
static unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


/* ===========================================================================================================
*
*       Function Name   : ping_address
**
**      Description     :The function takes address, timeout, num_ping, size as argument and 
                         performs ping functionality without using ping command. 
**
**      Returns         : Returns 0 on ping success and 1 on ping failure.
** =========================================================================================================== */

/*--------------------------------------------------------------------*/
/*--- ping - Create message and send it.                           ---*/
/*    return 0 is ping Ok, return 1 is ping not OK.                ---*/
/*--------------------------------------------------------------------*/
int scapi_ping(char *address, uint32 timeout, int num_ping, uint32 size)
{
    int sd = -1, iRet = 0, c = 0, pid = -1;
    int pktsize = 0, cnt = 1, i = 0;
    struct protoent *proto=NULL;
    char *msgbuf = NULL;
    struct hostent *hname;
    struct sockaddr_in addr_ping,*addr;
    struct timeval tv;
    struct sockaddr_in r_addr;
    socklen_t retlen=sizeof(r_addr);

    pid = getpid();
    proto = getprotobyname("ICMP");
    if(address == NULL)
    {
        iRet = -EXIT_FAILURE;
        goto errorHandler;
    }
    hname = gethostbyname(address);

    if (hname == NULL)
    {
        fprintf(stderr, "unknown host %s\n", address);
        iRet = -EXIT_FAILURE;
        goto errorHandler;
    }

    addr_ping.sin_family = hname->h_addrtype;
    addr_ping.sin_port = 0;
    addr_ping.sin_addr.s_addr = *(long*)hname->h_addr;

    addr = &addr_ping;

    //Calculate total packet size
    pktsize = size + sizeof(struct icmphdr);
    msgbuf=(char *) calloc(1,pktsize);
    if(msgbuf == NULL)
    {
	LOGF_LOG_ERROR("ERROR = %d --> %s\n", -errno, strerror(errno));
        iRet = -EXIT_FAILURE;
        goto errorHandler;
    }
    struct icmphdr *hdr = (struct icmphdr *) msgbuf;

    for ( i = 0; i < num_ping; i++)
    {
//Raw socket - if you use IPPROTO_ICMP, then kernel will fill in the correct ICMP header checksum, if IPPROTO_RAW, then it wont
       memset(msgbuf, 0, pktsize);

       sd = socket(AF_INET, SOCK_RAW, proto->p_proto);
       if ( sd < 0 )
       {
           perror("socket error");
           iRet = 1;
           goto errorHandler;
       }
       //allow socket to send datagrams to time to live 
       tv.tv_sec = 3;
       tv.tv_usec = 0;
       if ( setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) != 0)
       {
           perror("Setsockopt error");
           iRet = 1;
           goto errorHandler;
       }

       hdr->type = ICMP_ECHO;
       hdr->un.echo.id = pid;
       hdr->un.echo.sequence = cnt++;
       hdr->checksum = 0;
       hdr->checksum = checksum((unsigned short *)hdr, size );

       if(sendto(sd, msgbuf, pktsize, 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0)
       {
           perror("socket sendto error");
           iRet = 1;
           goto errorHandler;
       }

       c = recvfrom(sd, msgbuf, pktsize, 0, (struct sockaddr *) &r_addr, &retlen);
       if(c < 0)
       {
           perror("socket recvfrom error");
           iRet = -1;
           goto errorHandler;
       }
       else
       {
           iRet = 0;
           usleep(timeout);
           close(sd);
	   continue;
       }
    }

errorHandler:
    if (sd != -1)
       close(sd);

    free(msgbuf);
    return iRet;
}



struct globals {
    char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
} G;


/* ===========================================================================================================
*
*       Function Name   : ping6_address
**
**      Description     :The function takes address, timeout, num_ping, size as argument and performs
                         ping6 functionality by calling ping6 function
**
**      Returns         : Returns 0 on success and error on failure.
** =========================================================================================================== */

int scapi_ping6(char *address, uint32 timeout, int num_ping, uint32 size)
{
    int pingsock = -1, c = 0, i = 0;
    int sockopt, pktsize = 0, iRet =0, cnt = 1;
    char *msgbuf = NULL;
    uint16_t myid;
    struct len_and_sockaddr_d *lsa;
    struct in6_addr in6;
    struct sockaddr_in6 from;
    socklen_t fromlen = sizeof(from);

    lsa = calloc(1,LSA_LEN_SIZE_D + sizeof(struct sockaddr_in6));
    if(lsa == NULL)
    {
	LOGF_LOG_ERROR("ERROR = %d --> %s\n", -errno, strerror(errno));
        iRet = -EXIT_FAILURE;
        goto errorHandler;
    }

    iRet = inet_pton(AF_INET6, address, &in6);
    if(iRet <= 0)
    {
        struct hostent *hname;
        hname = gethostbyname2(address, AF_INET6);
        if (hname == NULL)
        {
                iRet = -EXIT_FAILURE;
		LOGF_LOG_ERROR("ERROR = %d\n", iRet);
                goto errorHandler;
        }

        lsa->len = sizeof(struct sockaddr_in6);
        lsa->u.sa.sa_family = AF_INET6;
        memcpy(&lsa->u.sin6.sin6_addr, &hname->h_name, 16);
        lsa->u.sin6.sin6_port = 0;
    }
    else
    {
        lsa->len = sizeof(struct sockaddr_in6);
        lsa->u.sa.sa_family = AF_INET6;
        lsa->u.sin6.sin6_addr = in6;
        lsa->u.sin6.sin6_port = 0;
    }

    myid = (uint16_t) getpid();

    pktsize = size + sizeof(struct icmp6_hdr);
    msgbuf=(char *) calloc(1,pktsize);
    if(msgbuf == NULL)
    {
	LOGF_LOG_ERROR("ERROR = %d --> %s\n", -errno, strerror(errno));
        iRet = -EXIT_FAILURE;
        goto errorHandler;
    }

    struct icmp6_hdr *pkt = (struct icmp6_hdr *) msgbuf;

    pkt->icmp6_type = ICMP6_ECHO_REQUEST;
    pkt->icmp6_seq = cnt++;
    pkt->icmp6_id = myid;
    pkt->icmp6_cksum = checksum((unsigned short *)pkt, size);

    for ( i = 0; i < num_ping; i++)
    {
        memset(msgbuf, 0, pktsize);
        pingsock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if ( pingsock < 0 )
        {
            perror("socket error");
            iRet = 1;
            goto errorHandler;
        }

        sockopt = offsetof(struct icmp6_hdr, icmp6_cksum);
        if (sockopt < 0)
        {
            perror("sockopt error");
            iRet = 1;
            goto errorHandler;
        }

        c = setsockopt(pingsock, SOL_RAW, IPV6_CHECKSUM, &sockopt, sizeof(sockopt));
        if (c < 0)
        {
            perror("setsockopt error");
            iRet = 1;
            goto errorHandler;
        }

        c = sendto(pingsock, msgbuf, pktsize, 0, &lsa->u.sa, lsa->len);
        if (c < 0)
        {
            perror("socket sendto error");
            iRet = 1;
            goto errorHandler;
        }

        /* listen for replies */
        c = recvfrom(pingsock, G.packet, sizeof(G.packet), 0, (struct sockaddr *) &from, &fromlen);
        if(c < 0)
        {
            perror("socket recvfrom error");
            iRet = -1;
            goto errorHandler;
        }
        else
        {
            iRet = 0;
            close(pingsock);
            usleep(timeout);
            continue;
        }
    }
errorHandler:
    if (pingsock != -1)
       close(pingsock);

    free(msgbuf);
    free(lsa);
    return iRet;

}

