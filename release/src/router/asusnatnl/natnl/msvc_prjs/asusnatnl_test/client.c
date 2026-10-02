/*******************************************************
*     MYCPLUS Sample Code - http://www.mycplus.com     *
*                                                     *
*   This code is made available as a service to our   *
*      visitors and is provided strictly for the      *
*               purpose of illustration.              *
*                                                     *
* Please direct all inquiries to saqib at mycplus.com *
*******************************************************/

// Module Name: client.c
//
// Description:
//    This sample is the echo client. It connects to the TCP server,
//    sends data, and reads data back from the server.
//
// Compile:
//    cl -o Client Client.c ws2_32.lib
//
// Command Line Options:
//    client [-p:x] [-s:IP] [-n:x] [-o]
//           -p:x      Remote port to send to
//           -s:IP     Server's IP address or hostname
//           -n:x      Number of times to send message
//           -o        Send messages only; don't receive
//
#ifdef WIN32
#include <winsock2.h>
#include <ws2def.h>
#else       
#include <sys/types.h>
#include <sys/socket.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <cmd_header.h>

#include <natnl_lib.h>

#define DEFAULT_COUNT       1
#define DEFAULT_PORT        5555
#define DEFAULT_BUFFER      1436
#define DEFAULT_MESSAGE     "This is a test of the emergency \
broadcasting system"

char  szServer[128],          // Server to connect to
      szMessage[1024];        // Message to send to sever
static int   iPort     = DEFAULT_PORT;  // Port on server to connect to
DWORD dwCount   = DEFAULT_COUNT; // Number of times to send message
BOOL  bSendOnly = FALSE;         // Send data only; don't receive

extern natnl_tnl_port natnl_tnl_ports[MAX_TUNNEL_PORT_COUNT];
extern int natnl_tnl_port_count;

//
// Function: usage:
//
// Description:
//    Print usage information and exit
//
/*void usage()
{
    printf("usage: client [-p:x] [-s:IP] [-n:x] [-o]\n\n");
    printf("       -p:x      Remote port to send to\n");
    printf("       -s:IP     Server's IP address or hostname\n");
    printf("       -n:x      Number of times to send message\n");
    printf("       -o        Send messages only; don't receive\n");
    ExitProcess(1);
}*/

//
// Function: ValidateArgs
//
// Description:
//    Parse the command line arguments, and set some global flags
//    to indicate what actions to perform
//
/*void ValidateArgs(int argc, char **argv)
{
    int                i;

    for(i = 1; i < argc; i++)
    {
        if ((argv[i][0] == '-') || (argv[i][0] == '/'))
        {
            switch (tolower(argv[i][1]))
            {
                case 'p':        // Remote port
                    if (strlen(argv[i]) > 3)
                        iPort = atoi(&argv[i][3]);
                    break;
                case 's':       // Server
                    if (strlen(argv[i]) > 3)
                        strcpy(szServer, &argv[i][3]);
                    break;
                case 'n':       // Number of times to send message
                    if (strlen(argv[i]) > 3)
                        dwCount = atol(&argv[i][3]);
                    break;
                case 'o':       // Only send message; don't receive
                    bSendOnly = TRUE;
                    break;
                default:
                    usage();
                    break;
            }
        }
    }
	}*/

int send_data_test()
{
	WSADATA       wsd;
	SOCKET        sClient;
	char          szBuffer[DEFAULT_BUFFER];
	int           ret;
	struct sockaddr_in server;
	struct hostent    *host = NULL;

	struct cmd_header ch;

	long file_size, file_read;
	FILE *pFile;

	int recv_bytes;
	time_t start, end;

	long opt;
	int optlen;

	// Parse the command line and load Winsock
	//
	//ValidateArgs(argc, argv);
#if 0
	strcpy(szServer, "114.37.178.62");
#else
	strcpy(szServer, "127.0.0.1");
#endif
	if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
	{
		printf("Failed to load Winsock library!\n");
		return 1;
	}
	strcpy(szMessage, DEFAULT_MESSAGE);
	//
	// Create the socket, and attempt to connect to the server
	//
	sClient = socket(AF_INET, SOCK_STREAM, 0);
	if (sClient == INVALID_SOCKET)
	{
		printf("socket() failed: %d\n", WSAGetLastError());
		return 2;
	}

	// Assigned lport from config
	if (natnl_tnl_port_count > 0) {
		iPort = atoi(natnl_tnl_ports[0].lport);
	}
	server.sin_family = AF_INET;
	server.sin_port = htons(iPort);
	server.sin_addr.s_addr = inet_addr(szServer);
	//
	// If the supplied server address wasn't in the form
	// "aaa.bbb.ccc.ddd" it's a hostname, so try to resolve it
	//
	if (server.sin_addr.s_addr == INADDR_NONE)
	{
		host = gethostbyname(szServer);
		if (host == NULL)
		{
			printf("Unable to resolve server: %s\n", szServer);
			return 3;
		}
		CopyMemory(&server.sin_addr, host->h_addr_list[0],
			host->h_length);
	}
	if (connect(sClient, (struct sockaddr *)&server,
		sizeof(server)) == SOCKET_ERROR)
	{
		printf("connect() failed: %d\n", WSAGetLastError());
		return 4;
	}
	// Send and receive data
	//
	ch.magic = htonl(CMD_MAGIC);
	ch.cmd = htonl(CMD_SEND_TEST);
	ch.data_size = htonl(0);

	printf("[client.c] htonl ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		ch.magic, ch.cmd, ch.data_size);

	ret = send(sClient, (char *)&ch, sizeof(ch), 0);
	if (ret == 0)
		return 5;
	else if (ret == SOCKET_ERROR)
	{
		printf("send() failed: %d\n", WSAGetLastError());
		return 6;
	}


	file_read = 0;
	recv_bytes = 0;
	start = time(NULL);

	while(1) {
		ret = recv(sClient, szBuffer, DEFAULT_BUFFER, 0);

		if (ret < 0)
			break;

		end = time(NULL);

		printf("Receive Data: %d KB/s, %ds\n", ret, end-start);
	}
	printf("[client.c] done!!!\n");
	fclose(pFile);
	closesocket(sClient);

	WSACleanup();
	return 0;
}

//
// Function: main
//
// Description:
//    Main thread of execution. Initialize Winsock, parse the
//    command line arguments, create a socket, connect to the
//    server, and then send and receive data.
//
int get_remote_file(char *file_name, int sock_type)
{
    WSADATA       wsd;
    SOCKET        sClient;
    char          szBuffer[DEFAULT_BUFFER];
    int           ret;
    struct sockaddr_in server;
	struct hostent    *host = NULL;
	struct sockaddr_in local;

	struct cmd_header ch;

	long file_size, file_read;
	FILE *pFile;

	int recv_bytes;
	time_t start, end;
	int server_len;

	int sobuf_size = 0;

    // Parse the command line and load Winsock
    //
    //ValidateArgs(argc, argv);
    strcpy(szServer, "192.158.100.215");
	//strcpy(szServer, "112.104.15.232");
    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
    {
        printf("Failed to load Winsock library!\n");
        return 1;
    }
    strcpy(szMessage, DEFAULT_MESSAGE);
    //
    // Create the socket, and attempt to connect to the server
    //
    sClient = socket(AF_INET, sock_type, 0);
    if (sClient == INVALID_SOCKET)
    {
        printf("socket() failed: %d\n", WSAGetLastError());
        return 2;
	}

	sobuf_size = 1024*1024*1024;
	setsockopt(sClient, SOL_SOCKET, SO_RCVBUF, (char *)&sobuf_size, sizeof(int));
	sobuf_size = 1024*1024*1024;
	setsockopt(sClient, SOL_SOCKET, SO_SNDBUF, (char *)&sobuf_size, sizeof(int));
	// Assigned lport from config
	if (natnl_tnl_port_count > 0) {
		iPort = atoi("50000");
	}
    server.sin_family = AF_INET;
    server.sin_port = htons(iPort);
    server.sin_addr.s_addr = inet_addr(szServer);
	server_len = sizeof(server);
    //
    // If the supplied server address wasn't in the form
    // "aaa.bbb.ccc.ddd" it's a hostname, so try to resolve it
    //
    if (server.sin_addr.s_addr == INADDR_NONE)
    {
        host = gethostbyname(szServer);
        if (host == NULL)
        {
            printf("Unable to resolve server: %s\n", szServer);
			return 3;
        }
        CopyMemory(&server.sin_addr, host->h_addr_list[0],
            host->h_length);
	}
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_family = AF_INET;
	local.sin_port = htons(0);

	if (sock_type == SOCK_DGRAM && bind(sClient, (struct sockaddr *)&local,
		sizeof(local)) == SOCKET_ERROR)
	{
		printf("bind() failed: %d\n", WSAGetLastError());
		return 3;
	}
	//if (sock_type == SOCK_STREAM)
	{
		if (connect(sClient, (struct sockaddr *)&server,
			sizeof(server)) == SOCKET_ERROR)
		{
			printf("connect() failed: %d\n", WSAGetLastError());
			return 4;
		}
	}
    // Send and receive data
    //

	ch.magic = htonl(CMD_MAGIC);
	ch.cmd = htonl(CMD_GET_FILE);
	ch.data_size = htonl(strlen(file_name));

	printf("[client.c] ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		CMD_MAGIC, CMD_GET_FILE, strlen(file_name));
	printf("[client.c] htonl ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		ch.magic, ch.cmd, ch.data_size);

	if (sock_type == SOCK_STREAM)
	{
		ret = send(sClient, (char *)&ch, sizeof(ch), 0);
		ret = send(sClient, file_name, strlen(file_name), 0);
	}
	else
	{
		ret = sendto(sClient, (char *)&ch, sizeof(ch), 0, (struct sockaddr *)&server, server_len);
		ret = sendto(sClient, file_name, strlen(file_name), 0, (struct sockaddr *)&server, server_len);
	}
    if (ret == 0)
        return 5;
    else if (ret == SOCKET_ERROR)
    {
        printf("send() failed: %d\n", WSAGetLastError());
        return 6;
    }

	if (sock_type == SOCK_STREAM)
		ret = recv(sClient, (char *)&file_size, sizeof(file_size), 0);
	else
		ret = recvfrom(sClient, (char *)&file_size, sizeof(file_size), 0, (struct sockaddr *)&server, &server_len);

    if (ret == 0)        // Graceful close
        return 7;
    else if (ret == SOCKET_ERROR)
    {
        printf("recv() failed: %d\n", WSAGetLastError());
        return 8;
    }
	file_size = ntohl(file_size);

	pFile = fopen(file_name, "wb");
	if (!pFile) {
		printf("[client.c] open file failed. file_name=[%s]\n", file_name);
		return 9;
	}

	file_read = 0;
	recv_bytes = 0;
	start = time(NULL);

	while(file_size > file_read) {
		if (sock_type == SOCK_STREAM)
			ret = recv(sClient, szBuffer, DEFAULT_BUFFER, 0);
		else
			ret = recvfrom(sClient, szBuffer, DEFAULT_BUFFER, 0, (struct sockaddr *)&server, &server_len);

		if (ret < 0)
			break;

		if (ret < DEFAULT_BUFFER)
		{
			printf("the length of received data is less than [%d/%d] [%d/%d].", ret, DEFAULT_BUFFER, file_read, file_size);
		}

		end = time(NULL);
		recv_bytes += ret;
		//printf("recv_bytes=%d, start=%lld, end=%lld, spent=%d\n", recv_bytes, start, end, (end-start));
		if ((end-start) > 0)
		{
			printf("Download Speed : %d KB/s\n", ((recv_bytes / (end-start) / 1024)));
			//printf("%d KB/s\n", 10);
			recv_bytes = 0;
			start = time(NULL);
		}

		file_read += ret;
		//printf("[client.c] file_read=[%d]\n", file_read);
		ret = fwrite(szBuffer, 1, ret, pFile);
		if (ret == 0) {
			fclose(pFile);
			return 10;
		}
	}
	printf("[client.c] done!!!\n");
	fclose(pFile);
    closesocket(sClient);

    WSACleanup();
    return 0;
}

//
// Function: main
//
// Description:
//    Main thread of execution. Initialize Winsock, parse the
//    command line arguments, create a socket, connect to the
//    server, and then send and receive data.
//
int get_remote_data(int data_size, int sock_type)
{
	WSADATA       wsd;
	SOCKET        sClient;
	char          szBuffer[DEFAULT_BUFFER];
	int           ret;
	struct sockaddr_in server;
	struct hostent    *host = NULL;

	struct cmd_header ch;

	long file_size, file_read;
	FILE *pFile;

	int recv_bytes, total_recv;
	time_t start, end;
	size_t buf_read;

	// Parse the command line and load Winsock
	//
	//ValidateArgs(argc, argv);
	strcpy(szServer, "127.0.0.1");
	//strcpy(szServer, "112.104.15.232");
	if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
	{
		printf("Failed to load Winsock library!\n");
		return 1;
	}
	strcpy(szMessage, DEFAULT_MESSAGE);
	//
	// Create the socket, and attempt to connect to the server
	//
	sClient = socket(AF_INET, sock_type, 0);
	if (sClient == INVALID_SOCKET)
	{
		printf("socket() failed: %d\n", WSAGetLastError());
		return 2;
	}
	// Assigned lport from config
	if (natnl_tnl_port_count > 0) {
		iPort = atoi(natnl_tnl_ports[0].lport);
	}
	server.sin_family = AF_INET;
	server.sin_port = htons(iPort);
	server.sin_addr.s_addr = inet_addr(szServer);
	//
	// If the supplied server address wasn't in the form
	// "aaa.bbb.ccc.ddd" it's a hostname, so try to resolve it
	//
	if (server.sin_addr.s_addr == INADDR_NONE)
	{
		host = gethostbyname(szServer);
		if (host == NULL)
		{
			printf("Unable to resolve server: %s\n", szServer);
			return 3;
		}
		CopyMemory(&server.sin_addr, host->h_addr_list[0],
			host->h_length);
	}
	if (connect(sClient, (struct sockaddr *)&server,
		sizeof(server)) == SOCKET_ERROR)
	{
		printf("connect() failed: %d\n", WSAGetLastError());
		return 4;
	}
	// Send and receive data
	//

	ch.magic = htonl(CMD_MAGIC);
	ch.cmd = htonl(CMD_GET_DATA);
	ch.data_size = htonl(data_size);
	start = time(NULL);
	recv_bytes = 0;

	printf("[client.c] htonl ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		ch.magic, ch.cmd, ch.data_size);
	while(1) {
		ret = send(sClient, (char *)&ch, sizeof(ch), 0);
		//printf("[client.c] total_sent=[%d]\n", ret);
		if (ret == 0)
			return 5;
		else if (ret == SOCKET_ERROR)
		{
			printf("send() failed: %d\n", WSAGetLastError());
			return 6;
		}

		total_recv = 0;
		recv_bytes = 0;
		memset(szBuffer, 0, DEFAULT_BUFFER);
		while (data_size > total_recv) {
			if ((data_size - total_recv) >= DEFAULT_BUFFER)
				buf_read = DEFAULT_BUFFER;
			else
				buf_read = (data_size - total_recv);

			ret = recv(sClient, szBuffer, buf_read, 0);

			if (ret < 0)
				break;

			recv_bytes += ret;
			end = time(NULL);
			if ((end-start) > 0)
			{
				printf("Download Speed : %d KB/s\n", ((recv_bytes / (end-start) / 1024)));
				recv_bytes = 0;
				start = time(NULL);
			}
			total_recv += ret;
			//printf("[client.c] total_sent=[%d]\n", total_sent);
			if (ret == 0) {
				//fclose(pFile);
				break;
			}

			memset(szBuffer, 0, DEFAULT_BUFFER);
		}
	}
	printf("[client.c] done!!!\n");
	fclose(pFile);
	closesocket(sClient);

	WSACleanup();
	return 0;
}

extern long get_file_size(const char *file_name);
//
// Function: main
//
// Description:
//    Main thread of execution. Initialize Winsock, parse the
//    command line arguments, create a socket, connect to the
//    server, and then send and receive data.
//
int put_local_file(char *file_name, int sock_type)
{
	WSADATA       wsd;
	SOCKET        sClient;
	char          szBuffer[DEFAULT_BUFFER];
	int           ret;
	struct sockaddr_in server;
	struct hostent    *host = NULL;

	struct cmd_header ch;

	long file_size, file_read;
	FILE *pFile;
	size_t buf_read;
	int sent_bytes;
	time_t start, end;

	// Parse the command line and load Winsock
	//
	//ValidateArgs(argc, argv);
	strcpy(szServer, "127.0.0.1");
	if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
	{
		printf("Failed to load Winsock library!\n");
		return 1;
	}
	strcpy(szMessage, DEFAULT_MESSAGE);
	//
	// Create the socket, and attempt to connect to the server
	//
	sClient = socket(AF_INET, sock_type, 0);
	if (sClient == INVALID_SOCKET)
	{
		printf("socket() failed: %d\n", WSAGetLastError());
		return 2;
	}
	// Assigned lport from config
	if (natnl_tnl_port_count > 0) {
		iPort = atoi(natnl_tnl_ports[0].lport);
	}
	server.sin_family = AF_INET;
	server.sin_port = htons(iPort);
	server.sin_addr.s_addr = inet_addr(szServer);
	//
	// If the supplied server address wasn't in the form
	// "aaa.bbb.ccc.ddd" it's a hostname, so try to resolve it
	//
	if (server.sin_addr.s_addr == INADDR_NONE)
	{
		host = gethostbyname(szServer);
		if (host == NULL)
		{
			printf("Unable to resolve server: %s\n", szServer);
			return 3;
		}
		CopyMemory(&server.sin_addr, host->h_addr_list[0],
			host->h_length);
	}
	if (connect(sClient, (struct sockaddr *)&server,
		sizeof(server)) == SOCKET_ERROR)
	{
		printf("connect() failed: %d\n", WSAGetLastError());
		return 4;
	}
	// Send and receive data
	//

	ch.magic = htonl(CMD_MAGIC);
	ch.cmd = htonl(CMD_PUT_FILE);
	ch.data_size = htonl(strlen(file_name));

	printf("[client.c] ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		CMD_MAGIC, CMD_PUT_FILE, strlen(file_name));
	printf("[client.c] htonl ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		ch.magic, ch.cmd, ch.data_size);

	// send command and data (file_name)
	ret = send(sClient, (char *)&ch, sizeof(ch), 0);
	ret = send(sClient, file_name, strlen(file_name), 0);
	if (ret == 0)
		return 5;
	else if (ret == SOCKET_ERROR)
	{
		printf("send() failed: %d\n", WSAGetLastError());
		return 6;
	}

	file_size = get_file_size(file_name);
	file_size = htonl(file_size);
	ret = send(sClient, (char *)&file_size, sizeof(file_size), 0);
	if (ret == 0)        // Graceful close
		return 7;
	else if (ret == SOCKET_ERROR)
	{
		printf("send() failed: %d\n", WSAGetLastError());
		return 8;
	}

	pFile = fopen(file_name, "rb");
	if (!pFile) {
		printf("[client.c] open file failed. file_name=[%s]\n", file_name);
		return 9;
	}

	file_read = 0;
	memset(szBuffer, 0, DEFAULT_BUFFER);
	fseek(pFile, 0, SEEK_SET);
	// read file to buffer and write to socket.
	sent_bytes = 0;
	start = time(NULL);
	while ((buf_read = fread(szBuffer, 1, DEFAULT_BUFFER, pFile))) {

		ret = send(sClient, szBuffer, buf_read, 0);

		if (ret < 0)
			break;

		sent_bytes += ret;
		end = time(NULL);
		if ((end-start) > 0)
		{
			printf("Upload Speed : %d KB/s\n", ((sent_bytes / (end-start) / 1024)));
			sent_bytes = 0;
			start = time(NULL);
		}
		if (ret == 0) {
			fclose(pFile);
			return 10;
		}

		memset(szBuffer, 0, DEFAULT_BUFFER);
	}
	fclose(pFile);
	closesocket(sClient);

	WSACleanup();
	return 0;
}
//
// Function: main
//
// Description:
//    Main thread of execution. Initialize Winsock, parse the
//    command line arguments, create a socket, connect to the
//    server, and then send and receive data.
//
int put_local_data(int data_size, int sock_type)
{
	WSADATA       wsd;
	SOCKET        sClient;
	char          szBuffer[DEFAULT_BUFFER];
	int           ret;
	struct sockaddr_in server;
	struct hostent    *host = NULL;

	struct cmd_header ch;

	long file_size, data_read;
	FILE *pFile;
	size_t buf_read;
	int sent_bytes, total_sent;

	int recv_bytes;
	time_t start, end;

	long opt;
	int optlen;

	// Parse the command line and load Winsock
	//
	//ValidateArgs(argc, argv);
#if 0
	strcpy(szServer, "114.37.178.62");
#else
	strcpy(szServer, "127.0.0.1");
#endif
	if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
	{
		printf("Failed to load Winsock library!\n");
		return 1;
	}
	strcpy(szMessage, DEFAULT_MESSAGE);
	//
	// Create the socket, and attempt to connect to the server
	//
	sClient = socket(AF_INET, sock_type, 0);
	if (sClient == INVALID_SOCKET)
	{
		printf("socket() failed: %d\n", WSAGetLastError());
		return 2;
	}

	// Assigned lport from config
	if (natnl_tnl_port_count > 0) {
		iPort = atoi(natnl_tnl_ports[0].lport);
	}
	server.sin_family = AF_INET;
	server.sin_port = htons(iPort);
	server.sin_addr.s_addr = inet_addr(szServer);
	//
	// If the supplied server address wasn't in the form
	// "aaa.bbb.ccc.ddd" it's a hostname, so try to resolve it
	//
	if (server.sin_addr.s_addr == INADDR_NONE)
	{
		host = gethostbyname(szServer);
		if (host == NULL)
		{
			printf("Unable to resolve server: %s\n", szServer);
			return 3;
		}
		CopyMemory(&server.sin_addr, host->h_addr_list[0],
			host->h_length);
	}
	if (connect(sClient, (struct sockaddr *)&server,
		sizeof(server)) == SOCKET_ERROR)
	{
		printf("connect() failed: %d\n", WSAGetLastError());
		return 4;
	}

	ch.magic = htonl(CMD_MAGIC);
	ch.cmd = htonl(CMD_PUT_DATA);
	ch.data_size = htonl(data_size);
	start = time(NULL);
	sent_bytes = 0;
	while(1) {
		ret = send(sClient, (char *)&ch, sizeof(ch), 0);
		//printf("[client.c] total_sent=[%d]\n", ret);
		if (ret == 0)
			return 5;
		else if (ret == SOCKET_ERROR)
		{
			printf("send() failed: %d\n", WSAGetLastError());
			return 6;
		}

		total_sent = 0;
		//sent_bytes = 0;
		memset(szBuffer, 0, DEFAULT_BUFFER);
		while (data_size > total_sent) {
			if ((data_size - total_sent) >= DEFAULT_BUFFER)
				buf_read = DEFAULT_BUFFER;
			else
				buf_read = (data_size - total_sent);
				
			ret = send(sClient, szBuffer, buf_read, 0);

			if (ret < 0)
				break;

			sent_bytes += ret;
			end = time(NULL);
			if ((end-start) > 0)
			{
				printf("Upload Speed : %d KB/s\n", ((sent_bytes / (end-start) / 1024)));
				sent_bytes = 0;
				start = time(NULL);
			}
			total_sent += ret;
			//printf("[client.c] total_sent=[%d]\n", total_sent);
			if (ret == 0) {
				//fclose(pFile);
				break;
			}

			memset(szBuffer, 0, DEFAULT_BUFFER);
		}
	}
	printf("[client.c] done!!!\n");
	closesocket(sClient);

	WSACleanup();
	return 0;
}
/************************ End of Client ********************/
