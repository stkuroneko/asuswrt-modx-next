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
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmd_header.h>

#include <natnl_lib.h>

#define DEFAULT_COUNT       1
#define DEFAULT_PORT        5555
#define DEFAULT_BUFFER      1024
#define DEFAULT_MESSAGE     "This is a test of the emergency \
broadcasting system"

char  szServer[128],          // Server to connect to
      szMessage[1024];        // Message to send to sever
static int   iPort     = DEFAULT_PORT;  // Port on server to connect to
DWORD dwCount   = DEFAULT_COUNT; // Number of times to send message
BOOL  bSendOnly = FALSE;         // Send data only; don't receive

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

//
// Function: main
//
// Description:
//    Main thread of execution. Initialize Winsock, parse the
//    command line arguments, create a socket, connect to the
//    server, and then send and receive data.
//
int get_romote_file(char *file_name)
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
    sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sClient == INVALID_SOCKET)
    {
        printf("socket() failed: %d\n", WSAGetLastError());
        return 2;
    }
	// Assigned lport from config
	if (natnl_srv_port_count > 0) {
		iPort = atoi(natnl_srv_ports[0].lport);
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
	ch.cmd = htonl(CMD_GET_FILE);
	ch.data_size = htonl(strlen(file_name));

	printf("[client.c] ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		CMD_MAGIC, CMD_GET_FILE, strlen(file_name));
	printf("[client.c] htonl ch.magic=%d, ch.cmd=%d, ch.data_size=%d\n", 
		ch.magic, ch.cmd, ch.data_size);

    ret = send(sClient, (char *)&ch, sizeof(ch), 0);
	ret = send(sClient, file_name, strlen(file_name), 0);
    if (ret == 0)
        return 5;
    else if (ret == SOCKET_ERROR)
    {
        printf("send() failed: %d\n", WSAGetLastError());
        return 6;
    }

    ret = recv(sClient, (char *)&file_size, sizeof(file_size), 0);
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
	while(file_size > file_read) {
		ret = recv(sClient, szBuffer, DEFAULT_BUFFER, 0);
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

extern long get_file_size(const char *file_name);
//
// Function: main
//
// Description:
//    Main thread of execution. Initialize Winsock, parse the
//    command line arguments, create a socket, connect to the
//    server, and then send and receive data.
//
int put_local_file(char *file_name)
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
    sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sClient == INVALID_SOCKET)
    {
        printf("socket() failed: %d\n", WSAGetLastError());
        return 2;
    }
	// Assigned lport from config
	if (natnl_srv_port_count > 0) {
		iPort = atoi(natnl_srv_ports[0].lport);
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
		CMD_MAGIC, CMD_GET_FILE, strlen(file_name));
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
	while ((buf_read = fread(szBuffer, 1, DEFAULT_BUFFER, pFile))) {
		ret = send(sClient, szBuffer, buf_read, 0);
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
/************************ End of Client ********************/
