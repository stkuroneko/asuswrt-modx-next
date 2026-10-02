
int sock_init(char* server_ip, int server_port, int * sock_fd);

int sock_connect(int sock_fd, struct sockaddr_in* sa, int sa_size);

int sock_send(int sock_fd, char* data_buf, int data_size);
int sock_recv(int sock_fd, char* data_buf, int data_size);
