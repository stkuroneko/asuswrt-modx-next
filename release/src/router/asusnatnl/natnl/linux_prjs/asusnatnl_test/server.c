
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
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <cmd_header.h>

#include <natnl_lib.h>
#include <pthread.h>

#ifdef __cplusplus
//extern "C" {
#endif

#define DEFAULT_PORT        8000
#define DEFAULT_BUFFER      1024

SOCKET        sListen;
static int    iPort      = DEFAULT_PORT; // Port to listen for clients on
BOOL   bInterface = FALSE,	 // Listen on the specified interface
       bRecvOnly  = FALSE;   // Receive data only; don't echo back
char   szAddress[128];       // Interface to listen for clients on

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

        ret = recv(sock, (char *)&ch, sizeof(ch), 0);

		ch.magic = ntohl(ch.magic);
		ch.cmd = ntohl(ch.cmd);
		ch.data_size = ntohl(ch.data_size);

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
				ret = recv(sock, file_name, ch.data_size, 0);
				if (ret == 0)        // Graceful close
					return 4;
				printf("[server.c] cmd GetFile. file_name=[%s]\n", file_name);

				file_size = get_file_size(file_name);
				file_size = htonl(file_size);
				ret = send(sock, (char *)&file_size, sizeof(file_size), 0);
				if (ret == 0)
					return 5;

				pFile = fopen(file_name, "rb");
				if (!pFile) {
					printf("[server.c] open file failed. file_name=[%s]\n", file_name);
					return 6;
				}
				memset(buf, 0, DEFAULT_BUFFER);
				fseek(pFile, 0, SEEK_SET);
				// read file to buffer and write to socket.
				while ((buf_read = fread(buf, 1, DEFAULT_BUFFER, pFile))) {
					ret = send(sock, buf, buf_read, 0);
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
				ret = recv(sock, file_name, ch.data_size, 0);
				if (ret == 0)        // Graceful close
					return 4;
				printf("[server.c] cmd GetFile. file_name=[%s]\n", file_name);

				ret = recv(sock, (char *)&file_size, sizeof(file_size), 0);
				if (ret == 0)
					return 5;

				file_size = ntohl(file_size);
				pFile = fopen(file_name, "wb");
				if (!pFile) {
					printf("[server.c] open file failed. file_name=[%s]\n", file_name);
					return 6;
				}

				file_read = 0;
				while(file_size > file_read) {
					ret = recv(sock, buf, DEFAULT_BUFFER, 0);
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
    sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sListen == SOCKET_ERROR)
    {
        printf("socket() failed: %d\n", WSAGetLastError());
        return 2;
    }
    // Select the local interface and bind to it
    //
	// Assigned lport from config
	if (natnl_srv_port_count > 0) {
		iPort = atoi(natnl_srv_ports[0].rport);
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

    hThread = CreateThread(NULL, 0, tcp_server,
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

#ifdef __cplusplus
//}
#endif
