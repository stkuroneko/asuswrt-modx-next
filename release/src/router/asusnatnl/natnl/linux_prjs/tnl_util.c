//----------

int tnl_send_header(struct cmd_header * ch)
{

}

int tnl_init_header(struct cmd_header* ch, char* filename, int file_cmd)
{
	ch->magic = htonl(CMD_MAGIC);
	ch->cmd = htonl(file_cmd);
	ch->data_size = htonl(strlen(filename));
	return 0;
}

int tnl_get_remote_filesize(int sockfd, int* filesize)
{
	int		err = -1;
	char	c_file_size[128];
    recv(sockfd, c_file_size, sizeof(c_file_size), 0);
	*filesize = atoi(c_file_size);
	return err;
}

int tnl_get_file(char* filename)
{
   int err = -1;
   return err;
}

