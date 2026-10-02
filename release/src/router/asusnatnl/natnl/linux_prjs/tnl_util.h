int tnl_send_header(struct cmd_header * ch);
int tnl_init_header(struct cmd_header* ch, char* filename, int file_cmd);
int tnl_get_remote_filesize(int sockfd, int* filesize);
int tnl_get_file(char* filename);
