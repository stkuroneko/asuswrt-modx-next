#include <socket.h>
//---------- socket utility
int sock_init(char* server_ip, int server_port, int * sock_fd)
{
    struct sockaddr_in	server;
    struct hostent		*host = NULL;
	int					err =-1;

    *sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sock_fd <0)
    {
		goto init_server_sock_error;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(server_port);
    server.sin_addr.s_addr = inet_addr(server_ip);
	bzero( &(server.sin_zero), 8 );

    if (server.sin_addr.s_addr == INADDR_NONE)
    {
        host = gethostbyname(server_ip);
        if (host == NULL)
        {
			goto init_server_sock_error;
        }
        //CopyMemory(&server.sin_addr, host->h_addr_list[0],
        memcpy(&server.sin_addr, host->h_addr_list[0],
            host->h_length);
    }
	err = 0;
init_server_sock_error:
	return err;
}

int sock_connect(int sock_fd, struct sockaddr_in* sa, int sa_size)
{
	return connect(sock_fd, sa, sa_size );	
} 

int sock_send(int sock_fd, char* data_buf, int data_size)
{
    return send(sock_fd, data_buf, data_size, 0);
}

int sock_recv(int sock_fd, char* data_buf, int data_size)
{
    return recv(sock_fd, data_buf, data_size, 0);
}


