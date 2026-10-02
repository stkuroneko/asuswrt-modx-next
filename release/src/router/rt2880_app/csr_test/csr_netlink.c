#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netlink.h>

#include "csr_netlink.h"

static RT2880_CSR_MSG   input_csr_msg;

int csr_msg_recv(RT2880_CSR_MSG* read_addr)
{
	static int nl_socket;
		
	struct nlmsghdr* nl_header;	
	RT2880_CSR_MSG*	recv_csr_msg;	

	unsigned int len;
	int addr_len;
	struct iovec 		iov;
	struct sockaddr_nl  sa_nl;
	fd_set	readfds;
	struct timeval	tv;
	char buf[1024];
	struct msghdr msg = {
		(void*)&sa_nl, sizeof(struct sockaddr_nl),
		&iov, 1,
		NULL, 0,
		0
	};
	
	
	iov.iov_base = buf;
	iov.iov_len  = sizeof(buf);
	
	
	// printf("start to receive msg...\n");
	nl_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_CSR);
	
	if (nl_socket == 0)
		printf("netlink socket creation failed!\n");

	memset(&sa_nl, 0, sizeof(struct sockaddr_nl));
	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_pid = 0;
	sa_nl.nl_groups = RA2882_CSR_GROUP;

	if (bind(nl_socket, (struct sockaddr*)&sa_nl, sizeof(struct sockaddr_nl)) < 0)
	{
		printf("Can't bind netlink socket::down!\n");
		return -1;
	}
	
	if(getsockname(nl_socket, (struct sockaddr*)&sa_nl, &addr_len) < 0)
	{
		printf("src_test: getsockname() failed!\n");	
		return -1;
	}
	
	if (addr_len != sizeof(struct sockaddr_nl))
	{
		printf("Wrong address length::down\n");
		return -1;	
	}
	if (sa_nl.nl_family != AF_NETLINK)
	{
		printf("Wrong address family::down\n");
		return -1;	
	}

	tv.tv_sec  = 0;
	tv.tv_usec = 50;
	
	FD_ZERO(&readfds);
	
	FD_SET(nl_socket, &readfds);
	
	select(nl_socket+1, &readfds, NULL, NULL, &tv);
	
//	printf("FD_ISSET()...\n");
	if (FD_ISSET(nl_socket, &readfds))
	{

		len = recvmsg(nl_socket, &msg, 0);
		
	//	printf("len -- %d\n", len);
		if ( len < 0) {
			printf("EOF on netlink::down");
			return -1;
		}
	}
	

	if (msg.msg_namelen != sizeof(struct sockaddr_nl))
	{
		printf("Netlink sender address length error!\n");
		return -1;
	}	
	

	nl_header = (struct nlmsghdr*)buf;
	
	if ( !nl_header )
		printf("error! nl_header structure not available\n");
		
	recv_csr_msg = NLMSG_DATA(nl_header);

#ifdef DEBUG	
	printf("csr_go: type is 0x%08x\n", nl_header->nlmsg_type);	
#endif

	if(!recv_csr_msg) {
		printf("error! csr_msg structure not available\n");
		close(nl_socket);
	}	

	// if ( input_csr_msg.address == read_addr->address)
		input_csr_msg.default_value = recv_csr_msg->default_value;
	// else
	//	perror("recv -- read failed\n");
#ifdef DEBUG
	printf("netlink receiver: value is 0x%08x\n", input_csr_msg.default_value);
#endif	
	

	close(nl_socket);	
	return input_csr_msg.default_value;
}


int csr_msg_send(RT2880_CSR_MSG* input_csr_msg)
{

	int seq = 0;
	struct sockaddr_nl addr;
	struct nlmsghdr *nl_header = NULL;
	
	unsigned char buf0[128], buf1[128];
	unsigned int *regval;
	int netlink_socket;
	RT2880_CSR_MSG* csr_msg;

	/* create the socket */
	netlink_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_CSR);

	if ( netlink_socket == 0 )
		printf("netlink socket creation failed!\n");

	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family 	= AF_NETLINK;
	addr.nl_pid 	= 0;	/* packets are destined for the kernel */
	addr.nl_groups	= 0;

	nl_header = (struct nlmsghdr *)buf0;
	nl_header->nlmsg_type 	= 0;
	nl_header->nlmsg_len 	= NLMSG_LENGTH(sizeof(RT2880_CSR_MSG));
	nl_header->nlmsg_flags 	= (NLM_F_REQUEST);
	nl_header->nlmsg_pid 	= getpid();
	nl_header->nlmsg_seq	= seq++;
	csr_msg = NLMSG_DATA(nl_header);
	csr_msg->enable 	= input_csr_msg->enable ;
	csr_msg->address	= input_csr_msg->address;
	csr_msg->write_mask	= input_csr_msg->write_mask;

	if (sendto(netlink_socket, (void*)nl_header, nl_header->nlmsg_len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_nl)) < 0) {
		printf("unable to send message.\n");
	}
	
	close(netlink_socket);
	return 0;
}
