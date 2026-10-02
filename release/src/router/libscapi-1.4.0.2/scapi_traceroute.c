/******************************************************************************

  Copyright (c) 2012, 2014, 2015
  Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/syscall.h>
#include <poll.h>
#include <arpa/inet.h>
#include <ltq_api_include.h>

//#pragma GCC diagnostic ignored "-Wsign-compare"

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
#define OPT_STRING "i:m:w:q:"
enum
{
	OPT_DEVICE       = (1 << 0),    /* i */
	OPT_MAX_TTL      = (1 << 1),   /* m */
	OPT_WAITTIME     = (1 << 2),    /* w */
	OPT_PROBES       = (1 << 3)    /* q */
};


/******************************************************************
 *     Description: returns time in milliseconds
 *******************************************************************/

static int get_mono(struct timespec *ts)
{
	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, ts))
		return -1;
	return 0;
}


static unsigned long monotonic_ms(void)
{
	struct timespec ts;
	if(get_mono(&ts))
		return -1;
	return ts.tv_sec * 1000ULL + ts.tv_nsec/1000000;
}
/********************************************************************
 *  Description: Tries to resolve the ip address into Name
 Input args: struct_inaddr which contains the ip address
Return: On Success, Returns pointer to host name
On Failure, Returns NULL
NOTE: It is the duty of the caller to free the pointer
 *********************************************************************/

static int inet_name(struct in_addr my_in_addr, char* host)
{
	const struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr = my_in_addr };

	return  getnameinfo((const struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), 0, 0, 0);
}
/**********************************************************************
 *    Description: Polls for input events on a socket
 Input args: socket file descriptor, timeout
Return: If no POLLIN till wait_time, Returns 0 (i.e returns 0 if timeout happens)
If there is a POLLIN, Returns a +ve value
 ***********************************************************************/
static int socket_timeout(int fd,int wait_time)
{
	struct pollfd pfd[1];

	pfd[0].fd = fd;
	pfd[0].events = POLLIN;
	return poll(pfd, 1, wait_time);
}


/**********************************************************************
 *    Description: Tries to bind the socket to an interface
Input: socket file descriptor, interface
Return: -1, if socket cannot be binded to that interface
0, if binded
 ***********************************************************************/
static int bindtodevice(int fd, const char *iface)
{
	int r;
	struct ifreq ifr;
	strncpy(ifr.ifr_name, iface,IFNAMSIZ);
	/* NB: passing (iface, strlen(iface) + 1) does not work!
	 * (maybe it works on _some_ kernels, but not on 2.6.26)
	 * Actually, ifr_name is at offset 0, and in practice
	 * just giving char[IFNAMSIZ] instead of struct ifreq works too.
	 * But just in case it's not true on some obscure arch... */
	r = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
	if (r)
	{
		perror("can't bind to interface specified, binded to default interface:");
		return -1;
	}
	return r;
}

/********************************************************************
 *    Description: Traces route
Input arguments: 1-destination name along with other options. 2-traceresults** to store the intermediate hops
Return: On success- Returns 0
On failure- Several error codes

Options possible: -w(timeout), -i(interface), -m(max hops)
ERRORS: -EINVAL for -m or -w , -q not in the range
EXIT_FAILURE - Arguments not provided, No root permissions, 2nd argument is NULL, destination name/address not provided,Unable to create socket/set socket options
-E2BIG - If trace_route's 1st arguemnt exceeds limit(this string is going to be splitted internally)
-ECOMM - unable to send data through Socket
-EHOSTUNREACH - If unable to resolve host name/address
MAX_HOP_EXCEED - If destination not reached in 'max hops' provided
DEST_REACHED (0) - If destination reached
Note: calling function should pass a TraceRouteResp* 
This function allocates dynamic memory for array of hop results. Calling function should free it

eg:- traceroute("-m 50 -w 5000 www.google.com",40, &trace_route_resp);
 **********************************************************************/
int scapi_traceroute(char *args,int pkt_size, TraceRouteResp_D *pTraceRouteResp)
{
	/*traceroute related vars*/
	struct sockaddr_in target;
	struct hostent* host = NULL;
	struct in_addr address;
	uint16_t port = 32768+666; /* udp dest port for probe packets */

	char cbName[128] = {0};

	int sock_rcv = -1,sock_send = -1;
	unsigned long t1 = 0, t2 =0 , start_time = 0, end_time = 0;
	int bytes = 0;
	socklen_t addrlen = sizeof(struct sockaddr);

	int timeout = 5;
	int max_hops = 30;
	int probes = 3;

	char interface[IFNAMSIZ] = {0};
	char rtt_cat[16] = {0};


	char dest_ip[32] = {0};
	char recv_buffer[BUFSIZ];
	char* send_buffer = NULL;
	struct iphdr *re_ip = NULL;
	struct icmphdr *re_icmp = NULL;
	int minpacket_size = sizeof(struct iphdr) + sizeof(struct udphdr);
	int packlen = 0;
	int ttl = 1;
	//~~~~~~~~~~~~~~~~~
	int nRet = 0;
	int opt = 0;

	int index = 0;
	char* argv[16]= {NULL};
	int argc = 0;
	char* args_rw = NULL;
	char* token = NULL;
	char** argv_p = NULL;
	unsigned long options = 0x0000;
	
	if(args == NULL || pTraceRouteResp == NULL)
	{   
		nRet = -EXIT_FAILURE;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		return nRet;
	}
	memset(pTraceRouteResp, 0, sizeof(TraceRouteResp_D));

	/*free this later*/
	args_rw = strdup(args);

	/*tokenizing for route_main() like functionality in busybox for specifing all the parameters in a single argument*/
	token = strtok(args_rw, " ");
	/*dummy string in argv[0] to mimic the behaviour of main() function whose argv[0] is program name. This is required for getopt() which is used below*/
	argv[0] = "xx";
	for(index = 1; (token != NULL)&&(index < 15); ++index)
	{
		argv[index] = token;
		token = strtok(NULL," ");
	}
	if(index > 14)
	{
		nRet = -E2BIG;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	/*delimiting post last arg with NULL to know the end*/
	argv[index] = NULL;
	argc = index;
	/*argv[1] NULL implies that we did not provide any arguments. argv[0] is a dummy string. No arguments.Just blank string provided for 'args'*/
	if(argv[1] == NULL)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	/* all the 'traceroute' command parameters are now stored in 'argv' array*/
	argv_p = argv;
	/* getopt() function gets all the options, i.e characters prefixing with '-', it re-arranges elements after argv[0] (coz argv[0] is program name for usual command line            arguments in argv array in the order of options first and non-option arguments later sequentially. Options with arguments are postfixed by ':' and the argument is st           ored in optarg variable in unistd.h as soon as that option is encountered
	*/
	/* resetting optint. Necessary since this is an api */
	optind = 1; 
	opt = getopt(argc, argv, OPT_STRING);
	while(opt != EOF)
	{
		switch(opt)
		{
			case 'm':
				max_hops = atoi(optarg);
				if(max_hops > 64 || max_hops < 1)
				{
					nRet = -EINVAL;
					LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
					goto returnHandler;
				}
				options |= OPT_MAX_TTL;
				break;
			case 'w':
				timeout = (int)strtol(optarg,NULL,10);
				if(timeout < 1)
				{
					nRet = -EINVAL;
					LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
					goto returnHandler;
				}
				options |= OPT_WAITTIME;
				break;
			case 'i':
				strcpy(interface,optarg);
				options |= OPT_DEVICE;
				break;
			case 'q':
				probes = (int)strtol(optarg,NULL,10);
				if(probes < 1 && probes > 3)
				{
					nRet = -EINVAL;
					LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
					goto returnHandler;
				}
				options |= OPT_PROBES;
				break;
			default:
				nRet = -EINVAL;
				LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
				goto returnHandler;
		}
		opt = getopt(argc, argv, OPT_STRING);
	}
	argv_p += optind;
	/*now argv_p points the first non-option argument, which would be target host*/

	/*ip+icmp for receive_buffer*/
	re_ip = (struct iphdr*)recv_buffer;
	re_icmp = (struct icmphdr*) (recv_buffer + sizeof(struct iphdr));

	/*no host name in argv*/
	if (argc < 1 || (argv_p[0] == NULL) )
	{
		nRet = -EXIT_FAILURE;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	start_time = monotonic_ms();
	/* Resolve the address.Takes some time */
	host = gethostbyname(argv_p[0]);
	if(host == NULL)
	{
		nRet = -EHOSTUNREACH;
		goto returnHandler;
	}
	strcpy(dest_ip,inet_ntoa(*(struct in_addr *)host->h_addr));

	target.sin_family = AF_INET;
	target.sin_addr.s_addr = inet_addr(dest_ip);
	target.sin_port = htons(port);

	/* Create a RAW socket */
	if((sock_rcv = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0)
	{
		perror("receive socket");
		nRet = -EXIT_FAILURE;
		goto returnHandler;
	}
	if((sock_send = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))<0)
	{
		perror("send socket");
		nRet = -EXIT_FAILURE;
		goto returnHandler;
	}
	if(pkt_size >= minpacket_size && pkt_size <= (64*1024))
	{
		/*free later*/
		if(!(send_buffer = malloc(pkt_size)))
		{
			perror("unable to create send buffer:");
			nRet = -errno;
			goto returnHandler;
		}
		packlen = pkt_size; 
	}
	/* revert to min packet size of if provided size if not sufficient for sending */
	else if(pkt_size < minpacket_size && (pkt_size>=1))
	{
		if(!(send_buffer = malloc(minpacket_size)))
		{
			perror("unable to create send buffer:");
			nRet = -errno;
			goto returnHandler;
		}
		packlen = minpacket_size;
	}
	/*if provided data block size not between [1:65535]*/
	else
	{
		nRet = -EINVAL;
		goto returnHandler;
	}

	pTraceRouteResp->pxRouteHops = (ROUTE_HOPS_D*)malloc(sizeof(ROUTE_HOPS_D)*(max_hops));
	if(!pTraceRouteResp->pxRouteHops)
	{
		perror("unable to create pxRouteHops array:");
		nRet = -errno;
		goto returnHandler;
	}
	ROUTE_HOPS_D* results = pTraceRouteResp->pxRouteHops;
	memset(results,0,sizeof(ROUTE_HOPS_D)*max_hops);
	/*bindtodevice() on success binds the socket to provided interface. On failure the socket will be binded to default interface.*/
	if(options & OPT_DEVICE)
	{
		bindtodevice(sock_send,interface);    
	}

OUTER_LOOP:
	for(;ttl <= max_hops;++ttl)
	{

		if(setsockopt(sock_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
		{
			perror("Could not set TTL:");
			nRet = -errno;
			goto returnHandler;
		}

		/* Send the packet */
		int z = 0;
		for(;z < probes; ++z)
		{
			t1 = monotonic_ms();
			bytes = sendto(sock_send,send_buffer,packlen,0,(struct sockaddr*)&target,sizeof(struct sockaddr));

			if (bytes == -1)
			{
				perror("send");
				nRet = -errno;
				goto returnHandler;
			}

			/*if there is a timeout, by default, the packet will be sent again with same ttl for 'probes' times(-q option). If there is a timeout for a probe, hop_r			tt_time field will mention that. These number of tries can be changed with -q option */  
			if(!socket_timeout(sock_rcv,timeout*1000))
			{
				/*final try*/
				if(z == (probes-1))
				{
					strcpy(results[(ttl)-1].hophost,"\0");
					strcpy(results[(ttl)-1].hophost_address,"\0");
					snprintf(rtt_cat, sizeof rtt_cat, "%d",timeout);
					snprintf(results[(ttl)-1].hop_rtt_time, 64, "%s%s",results[(ttl)-1].hop_rtt_time, rtt_cat);
					results[(ttl)-1].hop_err_code = re_icmp->type; //timeout error
					++ttl;
					goto OUTER_LOOP;
				}
				snprintf(rtt_cat, sizeof rtt_cat, "%d,",timeout);
				snprintf(results[(ttl)-1].hop_rtt_time, 64, "%s%s",results[(ttl)-1].hop_rtt_time, rtt_cat);
				continue;
			}
			else
				break;
		}

		bytes = recvfrom(sock_rcv,recv_buffer,BUFSIZ,0,(struct sockaddr*)NULL,&addrlen);
		t2 = monotonic_ms();
		if (bytes == -1)
		{
			perror("recv:");
			nRet = -errno;
			goto returnHandler;
		}

		address.s_addr = re_ip -> saddr;
		nRet = inet_name(address, cbName);
		/*inet_ntoa() allocates in static memory. So no need to free 'name_final'*/
		char* name_final = NULL;
		if(nRet == 0)
			name_final = cbName;
		else
			name_final = inet_ntoa(address);
		strcpy(results[(ttl)-1].hophost,name_final);
		strcpy(results[(ttl)-1].hophost_address,inet_ntoa(address));
		snprintf(rtt_cat, sizeof rtt_cat, "%d", (int)(t2-t1));
		snprintf(results[(ttl)-1].hop_rtt_time,64,"%s%s",results[(ttl)-1].hop_rtt_time,rtt_cat);
		results[(ttl)-1].hop_err_code = re_icmp->type;

		if (strcmp(dest_ip,inet_ntoa(address)) == 0)
		{
			nRet = DEST_REACHED;
			goto returnHandler;
		}
	}

	/*final destination not reached*/
	/*using -999 to make sure that it doesn't match with any of error values in errno.h*/
	nRet = MAX_HOP_EXCEED;  
returnHandler:
	end_time = monotonic_ms();
	/*if there are no errors and ttl > 1 implies that there are entries in pxRouteHops
	  else trace_route failed and iResponseTime and iRoutHopsNumberOfEntries will be 0 */

	/*if gethostbyname() cannot resolve the name*/
	if(nRet == -EHOSTUNREACH)
	{
		pTraceRouteResp->iResponseTime = 0;
		pTraceRouteResp->iRouteHopsNumberOfEntries = 0;
		strcpy(pTraceRouteResp->caDiagState, "Error_CannotResolveHostName");
	}
	/*There are entries in pxRouteHops but final destination not found. Reaching ret = MAX_HOP_EXCEED implies that we have exceeded our max hops*/
	else if(nRet == MAX_HOP_EXCEED && ttl > 1)
	{
		pTraceRouteResp->iResponseTime = end_time-start_time;
		pTraceRouteResp->iRouteHopsNumberOfEntries = ttl-1;
		strcpy(pTraceRouteResp->caDiagState, "Error_MaxHopCountExceeded");
	}
	/*destination found and trace_route succeded*/
	else if(nRet == DEST_REACHED)
	{
		pTraceRouteResp->iResponseTime = end_time-start_time;
		pTraceRouteResp->iRouteHopsNumberOfEntries = ttl;
		strcpy(pTraceRouteResp->caDiagState, "Complete");
	}
	/*trace_route failed*/
	else
	{
		pTraceRouteResp->iResponseTime = 0;
		pTraceRouteResp->iRouteHopsNumberOfEntries = 0;
		strcpy(pTraceRouteResp->caDiagState, "Error_Internal");
	}
	if(args_rw != NULL)
		free(args_rw);
	if(send_buffer != NULL)
		free(send_buffer);
	if(sock_rcv != -1)
		close(sock_rcv);
	if(sock_send != -1)
		close(sock_send);
	return nRet;
}





