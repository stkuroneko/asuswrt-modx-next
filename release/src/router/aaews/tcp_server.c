/***  TCP Server tcpserver.c 
 *  *
 *   * 利用 socket 介面設計網路應用程式
 *    * 程式啟動後等待 client 端連線，連線後印出對方之 IP 位址
 *     * 並顯示對方所傳遞之訊息，並回送給 Client 端。
 *      *
 *       */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#if defined(__GLIBC__) || defined(__UCLIBC__) /* not musl */
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include <string.h>
#include <tcp_server.h>
#include <unistd.h>	//read()
#include <arpa/inet.h>	//inet_ntoa()
#include <pthread.h>	//pthread_attr_init()

#define SERV_PORT 65525 


#define MAXNAME 1024


extern int errno;
CB_INFO g_cb_info;

//int tcp_server(CB_RECV recv_func )
void* tcp_server_thread(void* tdata )
{
	int socket_fd;      /* file description into transport */
	int recfd;     /* file descriptor to accept        */
	int length;     /* length of address structure      */
	int nbytes;     /* the number of read **/
	char buf[BUFSIZ];
	memset(buf, 0, sizeof(buf));
	struct sockaddr_in myaddr; /* address of this service */
	struct sockaddr_in client_addr; /* address of client    */
	CB_INFO* cb_info		= (CB_INFO*)tdata;
	CB_RECV rec_func		= cb_info->rec_func;
	CB_SEND send_func	= cb_info->send_func;
	/*                              
		*                               *      Get a socket into TCP/IP
		*                                */
	if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) <0) {
		perror ("socket failed");
		exit(1);
	}
   
	/*
		*  *    Set up our address
		*   */
	bzero ((char *)&myaddr, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(SERV_PORT);


	/*
		*  *     Bind to the address to which the service will be offered
		*   */
	if (bind(socket_fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) <0) {
		perror ("bind failed");
		exit(1);
	}


	/* 
		*  * Set up the socket for listening, with a queue length of 5
		*   */
	if (listen(socket_fd, 20) <0) {
		perror ("listen failed");
		exit(1);
	}
		/*
		*  * Loop continuously, waiting for connection requests
		*   * and performing the service
		*    */
	length = sizeof(client_addr);
	printf("Server is ready to receive !!\n");
	printf("Can strike Cntrl-c to stop Server >>\n");
	while (1) {
		printf("Accept ...... >>\n");
		if ((recfd = accept(socket_fd, 
				   (struct sockaddr *)&client_addr, &length)) <0) {
			 perror ("could not accept call");
			exit(1);
		}

		if ((nbytes = read(recfd, &buf, BUFSIZ)) < 0) {
			perror("read of data error nbytes !");
			exit (1);
		}

		int rec_status=-1;
		printf(" call cb_rec ...... >>\n");
		if(rec_func) {
			rec_status = (rec_func)(buf, nbytes);
		}
		printf("Create socket #%d form %s : %d\n", recfd, 
			inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port)); 
		printf("%s\n", buf);

		if(!rec_status){
			printf(" call cb_send ...... >>\n");
			if(send_func) (send_func)(recfd);
		}
	  /* return to client */
#if 0
	  if (write(recfd, &buf, nbytes) == -1) {
		 perror ("write to client error");
		 exit(1);
	  }
#endif
		close(recfd);
		printf("Can Strike Crtl-c to stop Server >>\n");
	}
	return 0;
}


int start_tcp_server(CB_RECV cb_recv, CB_SEND cb_send)
{
	int err = 0;
	pthread_t tid=0;
	pthread_attr_t attr;
	g_cb_info.rec_func	= cb_recv;
	g_cb_info.send_func = cb_send;

	pthread_attr_init(&attr);
#ifdef PTHREAD_STACK_SIZE
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
	err = pthread_create(&tid, &attr, tcp_server_thread, &g_cb_info );
	pthread_attr_destroy(&attr);
	return err;
}
