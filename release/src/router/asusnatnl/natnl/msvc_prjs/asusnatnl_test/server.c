
/*******************************************************/
//--------------------------------------------------------------------------//
/*************************** Server ********************/
//
// Module Name: server.c
//
// Description:
//    This example illustrates a simple TCP server that accepts
//    incoming client connections. Once a client connection is
//    established, a thread is spawned to read data from the
//    client and echo it back (if the echo option is not
//    disabled).
//
// Compile:
//    cl -o Server Server.c ws2_32.lib
//
// Command line options:
//    server [-p:x] [-i:IP] [-o]
//           -p:x      Port number to listen on
//           -i:str    Interface to listen on
//           -o        Receive only, don't echo the data back
//
#include <winsock2.h>

#include <stdio.h>
#include <stdlib.h>
#include <cmd_header.h>

#include <natnl_lib.h>

#ifdef __cplusplus
//extern "C" {
#endif

#define DEFAULT_PORT        8000
#define DEFAULT_BUFFER      1436

SOCKET        sListen;
static int    iPort      = DEFAULT_PORT; // Port to listen for clients on
BOOL   bInterface = FALSE,	 // Listen on the specified interface
       bRecvOnly  = FALSE;   // Receive data only; don't echo back
char   szAddress[128];       // Interface to listen for clients on

extern natnl_tnl_port natnl_tnl_ports[MAX_TUNNEL_PORT_COUNT];
extern int natnl_tnl_port_count;

//
// Function: usage
//
// Description:
//    Print usage information and exit
//
/*void usage()
{
    printf("usage: server [-p:x] [-i:IP] [-o]\n\n");
    printf("       -p:x      Port number to listen on\n");
    printf("       -i:str    Interface to listen on\n");
    printf("       -o        Don't echo the data back\n\n");
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
    int i;

    for(i = 1; i < argc; i++)
    {
        if ((argv[i][0] == '-') || (argv[i][0] == '/'))
        {
            switch (tolower(argv[i][1]))
            {
                case 'p':
                    iPort = atoi(&argv[i][3]);
                    break;
                case 'i':
                    bInterface = TRUE;
                    if (strlen(argv[i]) > 3)
                        strcpy(szAddress, &argv[i][3]);
                    break;
                   case 'o':
		           bRecvOnly = TRUE;
                       break;
                default:
                    usage();
                    break;
            }
        }
    }
	}*/

//
// Function: ClientThread
//
// Description:
//    This function is called as a thread, and it handles a given
//    client connection.  The parameter passed in is the socket
//    handle returned from an accept() call.  This function reads
//    data from the client and writes it back.
//
DWORD WINAPI IM_ClientThread(LPVOID lpParam)
{
	SOCKET        sock=(SOCKET)lpParam;
	int           ret;
	int sent_bytes, recv_bytes;
	time_t start, end;

	int sock_type;
	int opt_len = sizeof( int );

	int errno;


	//Sleep(35500);
	{
		int data_len;
		char buffer[1024];
		char *send_result = "OK";

		/*printf("~~~~~~~~ start to receive message\n");
		ret = recv(sock, (char *)&data_len, sizeof(int), 0);
		//data_len = ntohl(data_len);

		if (ret == 0)        // Graceful close
			return 0;
		else if (ret == SOCKET_ERROR)
		{
			printf("recv() failed: %d\n", WSAGetLastError());
			return 0;
		}
		printf("~~~~~~~~ data_len=%d\n", data_len);*/

		memset(buffer, 0, sizeof(buffer));
		//if (data_len <= sizeof(buffer))
		ret = recv(sock, (char *)&buffer, sizeof(buffer), 0);

		if (ret == 0)        // Graceful close
			return 0;
		else if (ret == SOCKET_ERROR)
		{
			printf("recv() failed: %d\n", WSAGetLastError());
			return 0;
		}

		printf("~~~~~~~~ data_len=%s\n", buffer);
		//else {
			// TODO
		//}

		data_len = strlen(send_result);
		/*ret = send(sock, (char *)&data_len, sizeof(int), 0);
		if (ret == 0)        // Graceful close
			return 0;
		else if (ret == SOCKET_ERROR)
		{
			printf("recv() failed: %d\n", WSAGetLastError());
			return 0;
		}
		printf("~~~~~~~~ sent data_len=%d\n", ret);*/

		ret = send(sock, send_result, data_len, 0);
		if (ret == 0)        // Graceful close
			return 0;
		else if (ret == SOCKET_ERROR)
		{
			printf("recv() failed: %d\n", WSAGetLastError());
			return 0;
		}
		printf("~~~~~~~~ sent data_len=%d\n", ret);
	}
	return 0;
}

long get_file_size(const char *file_name) {
	FILE *pFile = fopen(file_name, "r");
	long fileSize;
	if (!pFile) {
		printf("[server.c] open file failed. file_name=[%s]\n", file_name);
		return 0;
	}
	fseek(pFile, 0, SEEK_END); // seek to end of file
	fileSize = ftell(pFile);               // get current file pointer
	fseek(pFile, 0, SEEK_SET);  // seek back to beginning of file
	fclose(pFile);
	return fileSize;
}

//
// Function: ClientThread
//
// Description:
//    This function is called as a thread, and it handles a given
//    client connection.  The parameter passed in is the socket
//    handle returned from an accept() call.  This function reads
//    data from the client and writes it back.
//
DWORD WINAPI ClientThread(LPVOID lpParam)
{
    SOCKET        sock=(SOCKET)lpParam;
	int           ret;
	int sent_bytes, recv_bytes;
	time_t start, end;
	
	int sock_type;
	int opt_len = sizeof( int );

	int errno;

	ret = getsockopt( sock, SOL_SOCKET, SO_TYPE, &sock_type, &opt_len);
	if (ret)
		return 5;

	//Sleep(35500);

    while(1)
    {
        // Perform a blocking recv() call
        //
		struct cmd_header ch;
		char file_name[MAX_PATH];

		FILE *pFile;
		char buf[DEFAULT_BUFFER];
		size_t buf_read;
		long file_size, file_read;
		int sent_bytes, total_sent;
		int file_sent = 0;
		
		struct sockaddr_in from;
		int from_len = sizeof (from);

		if (sock_type == SOCK_STREAM)
			ret = recv(sock, (char *)&ch, sizeof(ch), 0);
		else
			ret = recvfrom(sock, (char *)&ch, sizeof(ch), 0, (struct sockaddr *)&from, &from_len);

		ch.magic = ntohl(ch.magic);
		ch.cmd = ntohl(ch.cmd);
		ch.data_size = ntohl(ch.data_size);

		printf("[client.c] htonl ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
			ch.magic, ch.cmd, ch.data_size);

        if (ret == 0)        // Graceful close
            break;
        else if (ret == SOCKET_ERROR)
        {
            printf("recv() failed: %d\n", WSAGetLastError());
            break;
        }

		// check if the magic of header is correct.
		if (ch.magic != CMD_MAGIC) {
			printf("[server.c] Incorrect cmd_header format.\n");
			return 3;
		}

		// check the command
		switch (ch.cmd) {
			case CMD_GET_FILE:
				memset(file_name, 0, sizeof(file_name)/sizeof(char));
				if (sock_type == SOCK_STREAM)
					ret = recv(sock, file_name, ch.data_size, 0);
				else
					ret = recvfrom(sock, file_name, ch.data_size, 0, (struct sockaddr *)&from, &from_len);
				
				printf("Received data form %s : %d\n", 
					inet_ntoa(from.sin_addr), htons(from.sin_port)); 

				if (ret == 0)        // Graceful close
					return 4;
				printf("[server.c] cmd GetFile. file_name=[%s]\n", file_name);

				file_size = get_file_size(file_name);
				file_size = htonl(file_size);
				if (sock_type == SOCK_STREAM)
					ret = send(sock, (char *)&file_size, sizeof(file_size), 0);
				else
					ret = sendto(sock, (char *)&file_size, sizeof(file_size), 0, (struct sockaddr *)&from, from_len);
				if (ret == 0)
					return 5;

				if (ret == -1)
				{
					printf("send() failed: %d\n", WSAGetLastError());
					return 8;
				}

				pFile = fopen(file_name, "rb");
				if (!pFile) {
					printf("[server.c] open file failed. file_name=[%s]\n", file_name);
					return 6;
				}
				memset(buf, 0, DEFAULT_BUFFER);
				fseek(pFile, 0, SEEK_SET);
				sent_bytes = 0;
				start = time(NULL);
				// read file to buffer and write to socket.
				while ((buf_read = fread(buf, 1, DEFAULT_BUFFER, pFile))) {
resend:
					if (sock_type == SOCK_STREAM)
						ret = send(sock, buf, buf_read, 0);
					else
						ret = sendto(sock, buf, buf_read, 0, (struct sockaddr *)&from, from_len);

					if (ret < 0)
					{
						if(errno != WSAEWOULDBLOCK)
						{
							printf("Socket error. Sending aborted.");
							break;
						}
						else
						{
							printf("Socket buffer full. Resend it.");
							goto resend;
						}
					}

					sent_bytes += ret;
					end = time(NULL);
					if ((end-start) > 0)
					{
						printf("Upload Speed : %d KB/s\n", ((sent_bytes / (end-start) / 1024)));
						sent_bytes = 0;
						start = time(NULL);
					}
					file_sent += ret;
					//printf("[client.c] file_sent=[%d]\n", file_sent);
					if (ret == 0) {
						fclose(pFile);
						return 7;
					}
					memset(buf, 0, DEFAULT_BUFFER);
				}
				fclose(pFile);
				break;
			case CMD_PUT_FILE:
				memset(file_name, 0, sizeof(file_name)/sizeof(char));
				if (sock_type == SOCK_STREAM)
					ret = recv(sock, file_name, ch.data_size, 0);
				else
					ret = recvfrom(sock, file_name, ch.data_size, 0, (struct sockaddr *)&from, &from_len);

				if (ret == 0)        // Graceful close
					return 4;
				printf("[server.c] cmd PutFile. file_name=[%s]\n", file_name);

				if (sock_type == SOCK_STREAM)
					ret = recv(sock, (char *)&file_size, sizeof(file_size), 0);
				else
					ret = recvfrom(sock, (char *)&file_size, sizeof(file_size), 0, (struct sockaddr *)&from, &from_len);
				if (ret == 0)
					return 5;
				printf("[server.c] file_size=[%d]\n", file_size);

				file_size = ntohl(file_size);
				pFile = fopen(file_name, "wb");
				if (!pFile) {
					printf("[server.c] open file failed. file_name=[%s]\n", file_name);
					return 6;
				}

				file_read = 0;
				recv_bytes = 0;
				start = time(NULL);
				while(file_size > file_read) {
					if (sock_type == SOCK_STREAM)
						ret = recv(sock, buf, DEFAULT_BUFFER, 0);
					else
						ret = recvfrom(sock, buf, DEFAULT_BUFFER, 0, (struct sockaddr *)&from, &from_len);

					if (ret < 0)
						break;

					if (ret < DEFAULT_BUFFER)
						printf("the length of sent data is less than %d.", DEFAULT_BUFFER);

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
					ret = fwrite(buf, 1, ret, pFile);
					if (ret == 0) {
						fclose(pFile);
						return 5;
					}
				}
				fclose(pFile);
				break;
			case CMD_SEND_TEST:
				start = time(NULL);
				while (1) {
					end = time(NULL);
					if (sock_type == SOCK_STREAM)
						ret = send(sock, buf, DEFAULT_BUFFER, 0);
					else
						ret = sendto(sock, buf, DEFAULT_BUFFER, 0, (struct sockaddr *)&from, from_len);

					if (ret < 0)
						break;

					printf("Send Data : %d KB/s, %ds\n", ret, end-start);

					Sleep(1000);
				}
				break;
			case CMD_GET_DATA:
				//memset(file_name, 0, sizeof(file_name)/sizeof(char));
				//ret = recv(sock, file_name, ch.data_size, 0);
				//if (ret == 0)        // Graceful close
				//	return 4;
				//printf("[server.c] cmd PutFile. file_name=[%s]\n", file_name);

				//ret = recv(sock, (char *)&file_size, sizeof(file_size), 0);
				//if (ret == 0)
				//	return 5;
				//file_size = ch.data_size;
				printf("[server.c] file_size=[%d]\n", file_size);

				//pFile = fopen(file_name, "wb");
				//if (!pFile) {
				//	printf("[server.c] open file failed. file_name=[%s]\n", file_name);
				//	return 6;
				//}

				file_read = 0;
				recv_bytes = 0;
				start = time(NULL);
				while(1) {
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
					memset(buf, 0, DEFAULT_BUFFER);
					while (ch.data_size > total_sent) {
						if ((ch.data_size - total_sent) >= DEFAULT_BUFFER)
							buf_read = DEFAULT_BUFFER;
						else
							buf_read = (ch.data_size - total_sent);

						if (sock_type == SOCK_STREAM)
							ret = send(sock, buf, buf_read, 0);
						else
							ret = sendto(sock, buf, buf_read, 0, (struct sockaddr *)&from, from_len);

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

						memset(buf, 0, DEFAULT_BUFFER);
					}
				}
				printf("end\n");
				//fclose(pFile);
				break;
			case CMD_PUT_DATA:
				//memset(file_name, 0, sizeof(file_name)/sizeof(char));
				//ret = recv(sock, file_name, ch.data_size, 0);
				//if (ret == 0)        // Graceful close
				//	return 4;
				//printf("[server.c] cmd PutFile. file_name=[%s]\n", file_name);

				//ret = recv(sock, (char *)&file_size, sizeof(file_size), 0);
				//if (ret == 0)
				//	return 5;
				//file_size = ch.data_size;
				printf("[server.c] file_size=[%d]\n", file_size);

				//pFile = fopen(file_name, "wb");
				//if (!pFile) {
				//	printf("[server.c] open file failed. file_name=[%s]\n", file_name);
				//	return 6;
				//}

				file_read = 0;
				sent_bytes = 0;
				start = time(NULL);
				while(1) {
					//if ((file_size - file_read) > DEFAULT_BUFFER)
					if (sock_type == SOCK_STREAM)
						ret = recv(sock, buf, DEFAULT_BUFFER, 0);
					else
						ret = recvfrom(sock, buf, DEFAULT_BUFFER, 0, (struct sockaddr *)&from, &from_len);
					//else
					//	ret = recv(sock, buf, (file_size - file_read), 0);

					if (ret < 0)
						break;

					end = time(NULL);
					sent_bytes += ret;
					//printf("recv_bytes=%d, start=%lld, end=%lld, spent=%d\n", recv_bytes, start, end, (end-start));
					if ((end-start) > 0)
					{
						printf("Download Speed : %d KB/s\n", ((sent_bytes / (end-start) / 1024)));
						//printf("%d KB/s\n", 10);
						recv_bytes = 0;
						start = time(NULL);
						//printf("1\n");
					}
					file_read += ret;
					//printf("[client.c] file_read=[%d]\n", file_read);
					//ret = fwrite(buf, 1, ret, pFile);
					if (ret == 0) {
						//fclose(pFile);
						//printf("2\n");
						break;
					}
				}
				printf("end\n");
				//fclose(pFile);
				break;
			default:
				printf("[server.c] Unknown command.\n");
				return 4;
		}
    }
    return 0;
}

//
// Function: main
//
// Description:
//    Main thread of execution. Initialize Winsock, parse the
//    command line arguments, create the listening socket, bind
//    to the local address, and wait for client connections.
//
DWORD WINAPI im_tcp_server(LPVOID lpPara)
{
	WSADATA       wsd;
	SOCKET        sClient;
	int           iAddrSize;
	HANDLE        hThread;
	DWORD         dwThreadId;
	SOCKADDR_IN local_service;
	SOCKADDR_IN client;
	int ret;

	//ValidateArgs(argc, argv);
	if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
	{
		printf("Failed to load Winsock!\n");
		return 1;
	}
	// Create our listening socket
	//
	sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sListen == INVALID_SOCKET)
	{
		printf("socket() failed: %d\n", WSAGetLastError());
		return 2;
	} 
	
	local_service.sin_family = AF_INET;
	local_service.sin_port = htons (8889);
	local_service.sin_addr.s_addr = inet_addr("127.0.0.1"); //htonl (INADDR_ANY);

	if (bind(sListen, (SOCKADDR *)&local_service, sizeof(local_service)) == SOCKET_ERROR)
	{
		printf("bind() failed: %d\n", WSAGetLastError());
		return 3;
	}
	if (listen(sListen, SOMAXCONN) == SOCKET_ERROR) {
		printf("listen() failed: %d\n", WSAGetLastError());
		return 4;
	}
	//
	// In a continous loop, wait for incoming clients. Once one
	// is detected, create a thread and pass the handle off to it.
	//
	while (1)
	{
		iAddrSize = sizeof(client);
		sClient = accept(sListen, NULL, NULL);
		if (sClient == INVALID_SOCKET)
		{
			printf("accept() failed: %d\n", WSAGetLastError());
			return 5;
		}
		//printf("Accepted client: %s:%d\n",
		//	inet_ntoa(client.sin_addr), ntohs(client.sin_port));

		hThread = CreateThread(NULL, 0, IM_ClientThread,
			(LPVOID)sClient, 0, &dwThreadId);
		if (hThread == NULL)
		{
			printf("CreateThread() failed: %d\n", GetLastError());
			return 5;
		}
		CloseHandle(hThread);
	}
	return 0;
}

//
// Function: main
//
// Description:
//    Main thread of execution. Initialize Winsock, parse the
//    command line arguments, create the listening socket, bind
//    to the local address, and wait for client connections.
//
DWORD WINAPI tcp_server(LPVOID lpPara)
{
    WSADATA       wsd;
    SOCKET        sClient;
    int           iAddrSize;
    HANDLE        hThread;
    DWORD         dwThreadId;
    struct sockaddr_in local,
                       client;

    //ValidateArgs(argc, argv);
    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
    {
        printf("Failed to load Winsock!\n");
        return 1;
    }
    // Create our listening socket
    //
    sListen = socket(AF_INET, SOCK_STREAM, 0);
    if (sListen == SOCKET_ERROR)
    {
        printf("socket() failed: %d\n", WSAGetLastError());
        return 2;
    }
    // Select the local interface and bind to it
    //
	// Assigned lport from config
	if (natnl_tnl_port_count > 0) {
		iPort = atoi(natnl_tnl_ports[0].rport);
	}
    if (bInterface)
    {
        local.sin_addr.s_addr = inet_addr(szAddress);
        if (local.sin_addr.s_addr == INADDR_NONE)
            ;//usage();
    }
    else
        local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_family = AF_INET;
    local.sin_port = htons(iPort);

    if (bind(sListen, (struct sockaddr *)&local,
            sizeof(local)) == SOCKET_ERROR)
    {
        printf("bind() failed: %d\n", WSAGetLastError());
        return 3;
    }
    listen(sListen, 8);
    //
    // In a continous loop, wait for incoming clients. Once one
    // is detected, create a thread and pass the handle off to it.
    //
    while (1)
    {
        iAddrSize = sizeof(client);
        sClient = accept(sListen, (struct sockaddr *)&client,
                        &iAddrSize);
        if (sClient == INVALID_SOCKET)
        {
            printf("accept() failed: %d\n", WSAGetLastError());
			return 4;
        }
        printf("Accepted client: %s:%d\n",
            inet_ntoa(client.sin_addr), ntohs(client.sin_port));

        hThread = CreateThread(NULL, 0, ClientThread,
                    (LPVOID)sClient, 0, &dwThreadId);
        if (hThread == NULL)
        {
            printf("CreateThread() failed: %d\n", GetLastError());
			return 5;
        }
        CloseHandle(hThread);
    }
    return 0;
}

int tcp_server_run(DWORD *dwThreadId) {

    HANDLE        hThread;

#if 0
    hThread = CreateThread(NULL, 0, tcp_server,
                0, 0, dwThreadId);
    if (hThread == NULL)
    {
        printf("CreateThread() failed: %d\n", GetLastError());
		return 1;
    }
	CloseHandle(hThread);
#endif
	hThread = CreateThread(NULL, 0, im_tcp_server,
		0, 0, dwThreadId);
	if (hThread == NULL)
	{
		printf("CreateThread() failed: %d\n", GetLastError());
		return 1;
	}
	CloseHandle(hThread);
	return 0;
}

int tcp_server_stop() {
    closesocket(sListen);

    WSACleanup();

	return 0;
}

//
// Function: main
//
// Description:
//    Main thread of execution. Initialize Winsock, parse the
//    command line arguments, create the listening socket, bind
//    to the local address, and wait for client connections.
//
DWORD WINAPI udp_server(LPVOID lpPara)
{
	WSADATA       wsd;
	SOCKET        sClient;
	int           iAddrSize;
	HANDLE        hThread;
	DWORD         dwThreadId;
	struct sockaddr_in local,
		client;

	int sobuf_size = 0;

	//ValidateArgs(argc, argv);
	if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
	{
		printf("Failed to load Winsock!\n");
		return 1;
	}
	// Create our listening socket
	//
	sListen = socket(AF_INET, SOCK_DGRAM, 0);
	if (sListen == SOCKET_ERROR)
	{
		printf("socket() failed: %d\n", WSAGetLastError());
		return 2;
	}
	//sobuf_size = 1024*1024*1024;
	//setsockopt(sListen, SOL_SOCKET, SO_RCVBUF, (char *)&sobuf_size, sizeof(int));
	//sobuf_size = 1024*1024*1024;
	//setsockopt(sListen, SOL_SOCKET, SO_SNDBUF, (char *)&sobuf_size, sizeof(int));
	// Select the local interface and bind to it
	//
	// Assigned lport from config
	if (natnl_tnl_port_count > 0) {
		iPort = atoi(natnl_tnl_ports[0].rport);
	}
	if (bInterface)
	{
		local.sin_addr.s_addr = inet_addr(szAddress);
		if (local.sin_addr.s_addr == INADDR_NONE)
			;//usage();
	}
	else
		local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_family = AF_INET;
	local.sin_port = htons(iPort);

	if (bind(sListen, (struct sockaddr *)&local,
		sizeof(local)) == SOCKET_ERROR)
	{
		printf("bind() failed: %d\n", WSAGetLastError());
		return 3;
	}
	//
	// In a continous loop, wait for incoming clients. Once one
	// is detected, create a thread and pass the handle off to it.
	//
	//while (1)
	//{
		hThread = CreateThread(NULL, 0, ClientThread,
			(LPVOID)sListen, 0, &dwThreadId);
		if (hThread == NULL)
		{
			printf("CreateThread() failed: %d\n", GetLastError());
			return 5;
		}
		CloseHandle(hThread);
	//}
	return 0;
}

int udp_server_run(DWORD *dwThreadId) {

	HANDLE        hThread;

	hThread = CreateThread(NULL, 0, udp_server,
		0, 0, dwThreadId);
	if (hThread == NULL)
	{
		printf("CreateThread() failed: %d\n", GetLastError());
		return 1;
	}
	CloseHandle(hThread);
	return 0;
}

int udp_server_stop() {
	closesocket(sListen);

	WSACleanup();

	return 0;
}

#ifdef __cplusplus
//}
#endif