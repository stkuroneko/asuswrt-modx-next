/*
 * Name : client.c
 * Author : Wen chi-ching
 * Date : 2009/10/14
 * Recieve file
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <client.h>
#include <j_log.h>
#include <cmd_header.h>
#include <natnl_lib.h>
#define THIS_FILE "natnl_linux/client.c"
 
#define DEFAULT_COUNT       1
#define DEFAULT_PORT        6666
#define DEFAULT_BUFFER      4096
#define DEFAULT_MESSAGE     "This is a test of the emergency broadcasting system"
static int iPort = DEFAULT_PORT;
#if 0

int client_test_tcp_send()
{
#define SERV_PORT	5134
#define MaX_DATA	1024
#define MAXNAME		1024
 int fd;      /* fd into transport provider */
 int i;      /* loops through user name */
 int length;     /* length of message */
 int fdesc;     /* file description */
 int ndata;     /* the number of file data */
 char data[MAXDATA]; /* read data form file */
 char data1[MAXDATA];  /*server response a string */
 char buf[BUFSIZ];     /* holds message from server */
 struct hostent *hp;   /* holds IP address of server */
 struct sockaddr_in myaddr;   /* address that client uses */
 struct sockaddr_in servaddr; /* the server's full addr */


 /*
  * Check for proper usage.
  */
#if 0
 if (argc < 3) {
  fprintf (stderr, 
   "Usage: %s host_name(IP address) file_name\n", argv[0]);
  exit(2);
 }
#endif
 /*
  *  Get a socket into TCP/IP
  */
 if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
  perror ("socket failed!");
  exit(1);
 }
 /*
  * Bind to an arbitrary return address.
  */
 bzero((char *)&myaddr, sizeof(myaddr));
 myaddr.sin_family = AF_INET;
 myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
 myaddr.sin_port = htons(0);


 if (bind(fd, (struct sockaddr *)&myaddr,
   sizeof(myaddr)) <0) {
  perror("bind failed!");
  exit(1);
 }
 /*
  * Fill in the server's address and the data.
  */


 bzero((char *)&servaddr, sizeof(servaddr));
 servaddr.sin_family = AF_INET;
 servaddr.sin_port = htons(SERV_PORT);


 hp = gethostbyname(argv[1]);
 if (hp == 0) {
  fprintf(stderr, 
   "could not obtain address of %s\n", argv[2]);
  return (-1);
 }


 bcopy(hp->h_addr_list[0], (caddr_t)&servaddr.sin_addr, 
  hp->h_length);
 /*
  * Connect to the server³s½u.
  */
 if (connect(fd, (struct sockaddr *)&servaddr, 
    sizeof(servaddr)) < 0) {
  perror("connect failed!");
  exit(1);
 }
 /**¶}°_ÀÉ®×Åª¨ú¤å¦r **/
 fdesc = open(argv[2], O_RDONLY);
 if (fdesc == -1) {
  perror("open file error!");
  exit (1);
 }
 ndata = read (fdesc, data, MAXDATA);
 if (ndata < 0) {
  perror("read file error !");
  exit (1);
 }
 data[ndata] = '\0';


 /* µo°e¸ê®Æµ¹ Server */
 if (write(fd, data, ndata) == -1) {
  perror("write to server error !");
  exit(1);
 }
 /** ¥Ñ¦øªA¾¹±µ¦¬¦^À³ **/
 if (read(fd, data1, MAXDATA) == -1) {
  perror ("read from server error !");
  exit (1);
 }
 /* ¦L¥X server ¦^À³ **/
 printf("%s\n", data1);


 close (fd);

}

#else
int client_test_tcp_send()
{
	char	szServer[128],          // Server to connect to
			szMessage[1024],        // Message to send to sever
			szBuffer[1500];
	struct	sockaddr_in address;
	int		sockfd;
	struct	hostent    *host = NULL;
	int		ret = -1;
#define test_tcp_port 7777
    strcpy(szServer, "192.168.0.198");
    //strcpy(szServer, "127.0.0.1");
	LOG_E("natnl_test_sock_send", "set szBuffer");
	int i =0;
	for(i =0; i< sizeof(szBuffer); i++)
		szBuffer[i] = i;

	if ( ( sockfd = socket(AF_INET, SOCK_STREAM, 0) ) == -1 ){
			goto client_test_tcp_send_exit; 
	}
	LOG_E("natnl_test_sock_send", "get sockfd=%d", sockfd);
	address.sin_family = AF_INET;
#if 0
	if (natnl_srv_port_count > 0) {
		iPort = atoi(natnl_srv_ports[0].lport);
		LOG_E(THIS_FILE, "client_test_tcp_send : iPort = %d", iPort);
	}else{
	   LOG_E(THIS_FILE, "natnl serv port coutn <0");
	}
#endif
	address.sin_port = htons(test_tcp_port);
	address.sin_addr.s_addr = inet_addr(szServer);
	bzero( &(address.sin_zero), 8 );
	if (address.sin_addr.s_addr == INADDR_NONE)
	{
		host = gethostbyname(szServer);
		if (host == NULL)
		{
			printf("Unable to resolve server: %s\n", szServer);
			goto client_test_tcp_send_exit; 
		}
		//CopyMemory(&server.sin_addr, host->h_addr_list[0],host->h_length);
		memcpy(&address.sin_addr, host->h_addr_list[0],host->h_length);
	}

	LOG_E("natnl_test_sock_send", "connect sockfd");
	if ( connect(sockfd, (struct sockaddr*)&address, sizeof(struct sockaddr)) == -1){
	LOG_E(THIS_FILE, " connect error =%d", errno);
		goto client_test_tcp_send_exit; 
	}

	LOG_E("natnl_test_sock_send", "sock send ..............");
    ret = send(sockfd, szBuffer, sizeof(szBuffer), 0);
	LOG_E("natnl_test_sock_send", "sock send return len =%d", ret);
client_test_tcp_send_exit:	
	return ret;
}
#endif
long get_file_size(const char *file_name) {
	FILE *pFile = fopen(file_name, "r");
	long fileSize;
	if (!pFile) {
	LOG_E(THIS_FILE, "fopen failed");
		printf("[server.c] open file failed. file_name=[%s]\n", file_name);
		return 0;
	}
	fseek(pFile, 0, SEEK_END); // seek to end of file
	fileSize = ftell(pFile);               // get current file pointer
	fseek(pFile, 0, SEEK_SET);  // seek back to beginning of file
	fclose(pFile);
	LOG_E(THIS_FILE, "get_file_size : filesize=%d", fileSize);
	return fileSize;
}

//int client_get(int argc, char* argv[]){
int put_local_file(char* filename, char* test_lport)
{
    //SOCKET        sClient;
    int        sClient;
    char          szBuffer[DEFAULT_BUFFER];
    int           ret;
    struct sockaddr_in server;
    struct hostent    *host = NULL;
	
	struct cmd_header ch;

	long file_size, file_read;
	FILE *pFile;
	size_t buf_read;
	char	szServer[128],          // Server to connect to
			szMessage[1024];        // Message to send to sever

    // Parse the command line and load Winsock
    //
    //ValidateArgs(argc, argv);
    strcpy(szServer, "127.0.0.1");
    strcpy(szMessage, DEFAULT_MESSAGE);
    //
    // Create the socket, and attempt to connect to the server
    //
	LOG_E(THIS_FILE, "put_local_file : .............1");
    sClient = socket(AF_INET, SOCK_STREAM, 0);
    if (sClient <0)
    {
		goto put_local_file_error;
    }
	// Assigned lport from config
//	if (natnl_srv_port_count > 0) {
	int iPort = atoi(test_lport);
	LOG_E(THIS_FILE, "put_local_file : .............2 iport=%d", iPort);
//	}
    server.sin_family = AF_INET;
    server.sin_port = htons(iPort);
    server.sin_addr.s_addr = inet_addr(szServer);
	bzero( &(server.sin_zero), 8 );
    //
    // If the supplied server address wasn't in the form
    // "aaa.bbb.ccc.ddd" it's a hostname, so try to resolve it
    //
    if (server.sin_addr.s_addr == INADDR_NONE)
    {
        host = gethostbyname(szServer);
        if (host == NULL)
        {
			goto put_local_file_error;
        }
        //CopyMemory(&server.sin_addr, host->h_addr_list[0],
        memcpy(&server.sin_addr, host->h_addr_list[0],
            host->h_length);
    }
	LOG_E(THIS_FILE, "put_local_file : .............3");
    if (connect(sClient, (struct sockaddr *)&server,
        sizeof(server)) == -1)
    {
			goto put_local_file_error;
    }
    // Send and receive data
    //
	char remote_filename[256]={0};
	char* ftmp = strrchr(filename, '/');
LOG_E(THIS_FILE, "ftmp = %s", ftmp);
	char* fn = (char*)(ftmp +1);
    strcpy(remote_filename, fn);
LOG_E(THIS_FILE, "remote file name = %s", remote_filename);
	ch.magic = htonl(CMD_MAGIC);
	ch.cmd = htonl(CMD_PUT_FILE);
//	ch.data_size = htonl(strlen(filename));
	ch.data_size = htonl(strlen(remote_filename));

	printf("[client.c] ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		CMD_MAGIC, CMD_GET_FILE, strlen(remote_filename));
	printf("[client.c] htonl ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		ch.magic, ch.cmd, ch.data_size);

	// send command and data (file_name)
	LOG_E(THIS_FILE, "Send file name =%s", filename);
    ret = send(sClient, (char *)&ch, sizeof(ch), 0);
//	ret = send(sClient, filename, strlen(filename), 0);
	ret = send(sClient, remote_filename, strlen(remote_filename), 0);
    if (ret == 0)
	   goto put_local_file_error;
	file_size = get_file_size(filename);
	file_size = htonl(file_size);
	LOG_E(THIS_FILE, "put file size=%d", file_size);
    ret = send(sClient, (char *)&file_size, sizeof(file_size), 0);
	if(!ret) 
	   goto put_local_file_error;

	//pFile = fopen(filename, "rb");
	pFile = fopen(filename, "rb");
	if (!pFile) {
		printf("[client.c] open file failed. file_name=[%s]\n", filename);
		goto put_local_file_error;
	}

	file_read = 0;
	memset(szBuffer, 0, DEFAULT_BUFFER);
	fseek(pFile, 0, SEEK_SET);
	// read file to buffer and write to socket.
	while ((buf_read = fread(szBuffer, 1, DEFAULT_BUFFER, pFile))) {
		ret = send(sClient, szBuffer, buf_read, 0);
		LOG_E(THIS_FILE, "Send buffer ret=%d", ret);
		if (ret == 0) {
			fclose(pFile);
			break;
		}
		memset(szBuffer, 0, DEFAULT_BUFFER);
	}
put_local_file_error:
	if(pFile)	fclose(pFile);
//    if(sClient)	closesocket(sClient);
    if(sClient)	close(sClient);
    return 0;
}



int get_remote_file(char* filename, char* test_lport)
{
	int		sockfd, numbytes;
    char	szBuffer[DEFAULT_BUFFER];
	struct	sockaddr_in address;
	FILE *	fp;
	struct	cmd_header ch;
	char	szServer[128],          // Server to connect to
			szMessage[1024];        // Message to send to sever
	struct	hostent    *host = NULL;
	long	file_size=0;
	long	file_read=0;
	int		ret;

    strcpy(szServer, "127.0.0.1");
    strcpy(szMessage, DEFAULT_MESSAGE);
	//TCP socket
	LOG_E(THIS_FILE, "get_remote_file 1");
	if ( ( sockfd = socket(AF_INET, SOCK_STREAM, 0) ) == -1 ){
		perror("socket");
		exit(1);
	}
 
	//Initial, connect to port 2323

//	int	iPort = atoi(test_lport); 
	//LOG_E(THIS_FILE, "get_remote_file  connect iPort =%d", iPort);
	address.sin_family = AF_INET;
	if (natnl_srv_port_count > 0) {
		iPort = atoi(natnl_srv_ports[0].lport);
	}else{
		LOG_E(THIS_FILE, "natnl serv port coutn <0");
	}
	LOG_E(THIS_FILE, "client_test_tcp_send : iPort = %d", iPort);
	address.sin_port = htons(iPort);
	address.sin_addr.s_addr = inet_addr(szServer);
	bzero( &(address.sin_zero), 8 );
 
	LOG_E(THIS_FILE, "get_remote_file 2");
	if (address.sin_addr.s_addr == INADDR_NONE)
	{
		host = gethostbyname(szServer);
		if (host == NULL)
		{
			printf("Unable to resolve server: %s\n", szServer);
			return 3;
		}
		//CopyMemory(&server.sin_addr, host->h_addr_list[0],host->h_length);
		memcpy(&address.sin_addr, host->h_addr_list[0],host->h_length);
	}

	//Connect to server
	if ( connect(sockfd, (struct sockaddr*)&address, sizeof(struct sockaddr)) == -1){
	LOG_E(THIS_FILE, "get_remote_file  connect error =%d", errno);
//		perror("connect");
//		exit(1);
		goto get_remote_file_error; 
	}

	// Send and receive data
    //
	char remote_filename[256]={0};
	char* fn = strrchr(filename, '/')+1;
	strcpy(remote_filename, fn);
	LOG_E(THIS_FILE, "remote filename =%s", remote_filename);	

	ch.magic = htonl(CMD_MAGIC);
	ch.cmd = htonl(CMD_GET_FILE);
//	ch.data_size = htonl(strlen(filename));
	ch.data_size = htonl(strlen(remote_filename));

	LOG_E(THIS_FILE, "[client.c] ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		CMD_MAGIC, CMD_GET_FILE, strlen(remote_filename));
	LOG_E(THIS_FILE, "[client.c] htonl ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		ch.magic, ch.cmd, ch.data_size);

	LOG_E(THIS_FILE, "send header");
    ret = send(sockfd, (char *)&ch, sizeof(ch), 0);
	ret = send(sockfd, remote_filename, strlen(remote_filename), 0);
	LOG_E(THIS_FILE, "send header ret =%d", ret);
    if (ret == 0)
        goto get_remote_file_error;
	/*
    else if (ret == SOCKET_ERROR)
    {
        printf("send() failed: %d\n", WSAGetLastError());
        return 6;
    }*/

	LOG_E(THIS_FILE, "recv get file size ");
    ret = recv(sockfd, (char *)&file_size, sizeof(file_size), 0);
	LOG_E(THIS_FILE, "recv file size=%d ", file_size);
    if (ret == 0)        // Graceful close
	   goto get_remote_file_error;
     //   return 7;
	/*
    else if (ret == SOCKET_ERROR)
    {
        printf("recv() failed: %d\n", WSAGetLastError());
        return 8;
    }*/
	file_size = ntohl(file_size);
LOG_E(THIS_FILE, "file_size =%d", file_size);

 
	LOG_E(THIS_FILE, "get_remote_file 3");
	//Open file
#if 0
	char save_path[100]={0};
	sprintf(save_path, "/sdcard/%s",filename );
	if ( (fp = fopen(save_path, "wb")) == NULL){
#else 

	if ( (fp = fopen(filename, "wb")) == NULL){
#endif
	LOG_E(THIS_FILE, "get_remote_file  connect error =%s", dlerror());
	//	perror("fopen");
	//	exit(1);
		goto get_remote_file_error;
	}
 
	LOG_E(THIS_FILE, "get_remote_file 4");
	//Receive file from server
#if 0
	while(1){
	LOG_E(THIS_FILE, "get_remote_file read socket fd=%d", sockfd);
		numbytes = read(sockfd, buf, sizeof(buf));
		LOG_E(THIS_FILE, "get_remote_file read %d bytes, ", numbytes);
		if(numbytes == 0){
			break;
		}
		LOG_E(THIS_FILE, "get_remote_file write %d bytes, ", numbytes);
		numbytes = fwrite(buf, sizeof(char), numbytes, fp);
		LOG_E(THIS_FILE, "get_remote_file really fwrite %d bytes\n", numbytes);
	}
#else
	while(file_size > file_read) {
		LOG_E(THIS_FILE, "call recv for szBuffer");
		ret = recv(sockfd, szBuffer, DEFAULT_BUFFER, 0);
		LOG_E(THIS_FILE, "szBuffer =%s, ret=%d", szBuffer, ret);
		file_read += ret;
		//printf("[client.c] file_read=[%d]\n", file_read);
		ret = fwrite(szBuffer, 1, ret, fp);
		if (ret == 0) {
			fclose(fp);
			break;
		//	return 10;
		}
	}

#endif

	LOG_E(THIS_FILE, "get_remote_file 5 return");
get_remote_file_error:
	if(fp)		fclose(fp);
	if(sockfd)	close(sockfd);
	return 0;
}
