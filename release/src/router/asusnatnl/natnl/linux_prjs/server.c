/*
 * Name : server.c
 * Author : Wen chi-ching
 * Date : 2009/10/14
 * Send file
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <server.h>
#include <pthread.h>
#include <j_log.h>
#include <natnl_lib.h>
#include <cmd_header.h>

#define THIS_FILE "server.c"
#define MAX_PATH 128
#define DEFAULT_BUFFER      4096
#define DEFAULT_REMOTE_PORT "8888"


//SRV_THREAD_INFO srv_thr_info;
PSRV_THREAD_INFO pSrv_info;

int tcp_server_stop(int listen_fd)
{
	if(listen_fd>0) close(listen_fd);	
	return 0;
}

void* ClientThread(void* lpParam)
{
//    SOCKET        sock=(SOCKET)lpParam;
    int				ret;
	PCL_THR_INFO	pCli_info	= (PCL_THR_INFO)lpParam;
	int				sock		= pCli_info->server_accept_sock;
	int				exit_val=-1;
LOG_E(THIS_FILE, "ClientThread : sock=%d", sock);
    while(1)
    {
        // Perform a blocking recv() call
        //
		struct	cmd_header ch;
		char	file_name[MAX_PATH];

		FILE *	pFile;
		char	buf[DEFAULT_BUFFER];
		size_t	buf_read;
		long	file_size, file_read;

        ret = recv(sock, (char *)&ch, sizeof(ch), 0);

		ch.magic = ntohl(ch.magic);
		ch.cmd = ntohl(ch.cmd);
		ch.data_size = ntohl(ch.data_size);
		if(ret == 0) 
		   break;
		else if(ret < 0){
			LOG_E(THIS_FILE, "ClientThread : error =%d, ch=%s", errno, ch);
			exit_val =-1;
			goto ClientThread_end;
		}
/*
        if (ret == 0)        // Graceful close
            break;
        else if (ret == SOCKET_ERROR)
        {
            printf("recv() failed: %d\n", WSAGetLastError());
            break;
        }
*/
		// check if the magic of header is correct.
		if (ch.magic != CMD_MAGIC) {
			//printf("[server.c] Incorrect cmd_header format.\n");
			LOG_E(THIS_FILE, "ClientThread : ch.magic != CMD_MAGIC");
			exit_val =-1;
			goto ClientThread_end;
			//return 3;
		}

		// check the command
		LOG_E(THIS_FILE,"ClientThread : cmd =%d", ch.cmd);
		switch (ch.cmd) {
			case CMD_GET_FILE:
				LOG_E(THIS_FILE, "ClientThread: CMD_GET_FILE");
				memset(file_name, 0, sizeof(file_name)/sizeof(char));
				ret = recv(sock, file_name, ch.data_size, 0);
				if (ret == 0){        // Graceful close
					exit_val = -1;
					goto ClientThread_end;
				}
				LOG_E(THIS_FILE," cmd GetFile. file_name=[%s]\n", file_name);

				char get_path_tmp[MAX_PATH]={0}; 
				sprintf(get_path_tmp,"/sdcard/%s",file_name);
				memset(file_name, 0, sizeof(file_name));
				strcpy(file_name, get_path_tmp);
				LOG_E(THIS_FILE, "ClientThread : get_path_tmp =%s, ret=%d", get_path_tmp,ret);
				LOG_E(THIS_FILE, "ClientThread : file_name =%s", file_name);

				file_size = get_file_size(file_name);
				LOG_E(THIS_FILE," cmd GetFile. file_size=%d", file_size);
				file_size = htonl(file_size);
				ret = send(sock, (char *)&file_size, sizeof(file_size), 0);
				if (ret == 0){
					exit_val = -1;
					goto ClientThread_end;
				}
				pFile = fopen(file_name, "rb");
				if (!pFile) {
					LOG_E(THIS_FILE,"open file failed. file_name=[%s], error=%d", file_name,errno);
					exit_val = -1;
					goto ClientThread_end;
				}
				memset(buf, 0, DEFAULT_BUFFER);
				fseek(pFile, 0, SEEK_SET);
				// read file to buffer and write to socket.
				while ((buf_read = fread(buf, 1, DEFAULT_BUFFER, pFile))) {
					ret = send(sock, buf, buf_read, 0);
					if (ret == 0) {
						fclose(pFile);
						exit_val = -1;
						goto ClientThread_end;
					}
					memset(buf, 0, DEFAULT_BUFFER);
				}
				fclose(pFile);
				break;
			case CMD_PUT_FILE:
				LOG_E(THIS_FILE, "ClientThread: CMD_PUT_FILE");
				memset(file_name, 0, sizeof(file_name)/sizeof(char));
				ret = recv(sock, file_name, ch.data_size, 0);
				if (ret == 0){        // Graceful close
					exit_val = -1;
					goto ClientThread_end;
				}
				LOG_E(THIS_FILE, "cmd PUtFile. file_name=[%s]\n", file_name);

				ret = recv(sock, (char *)&file_size, sizeof(file_size), 0);
				if (ret == 0){
					exit_val = -1;
					goto ClientThread_end;
				}

				file_size = ntohl(file_size);
				LOG_E(THIS_FILE, "cmd PUtFile. filesize=[%d]\n", file_size);
				char put_filename[MAX_PATH]={0};
				sprintf(put_filename,"/sdcard/%s",file_name);
				memset(file_name, 0, sizeof(file_name)/sizeof(char));
				strcpy(file_name, put_filename);
				
				pFile = fopen(file_name, "wb");
				if (!pFile) {
					LOG_E(THIS_FILE," open file failed. file_name=[%s]\n", file_name);
					exit_val = -1;
					goto ClientThread_end;
				}

				file_read = 0;
				LOG_E(THIS_FILE, "recieve & save file");
				while(file_size > file_read) {
					ret = recv(sock, buf, DEFAULT_BUFFER, 0);
					file_read += ret;
					//printf("[client.c] file_read=[%d]\n", file_read);
					ret = fwrite(buf, 1, ret, pFile);
					if (ret == 0) {
						fclose(pFile);
						exit_val = -1;
						goto ClientThread_end;
					}
				}
				fclose(pFile);
				break;
			default:
				LOG_E(THIS_FILE, " Unknown command.\n");
				goto ClientThread_end;
		}
    }
	exit_val = 0;
ClientThread_end:
	if(sock >0 )					close(sock);
	pthread_exit(&exit_val);
    return 0;
}

void* tcp_server_thread(void * arg)
{
	int		sockfd, new_fd, numbytes, sin_size;
	char	buf[1024];
	char	filename[128];
	struct	sockaddr_in my_addr;
	struct	sockaddr_in their_addr;
	struct	stat filestat;
	FILE	*fp;
	int		iPort;
	int		s;
	int		exit_val = -1;

//	PSRV_THREAD_INFO	*pTmp = (PSRV_THREAD_INFO)arg;
	PSRV_THREAD_INFO	srv_info = pSrv_info; //(PSRV_THREAD_INFO)*pTmp;
	memset(filename, 0, sizeof(filename));
//	strcpy(filename , srv_info->filename);
	//TCP socket
//	fprintf(stderr, "...1\n");
	LOG_E(THIS_FILE, "tcp_server_thread : ...1-1, srv_info=%p", srv_info);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0 ){
	   exit_val = -1;
	   goto tcp_server_thread_end;
	}
	LOG_E(THIS_FILE, "tcp_server_thread : ...1-2 sockfd=%d", sockfd);
	srv_info->srv_sockfd = sockfd;
//	iPort = atoi(natnl_srv_ports[0].rport);
	iPort = atoi(DEFAULT_REMOTE_PORT);
 
	//Initail, bind to port 2323 
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(iPort);
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bzero( &(my_addr.sin_zero), 8 );
 
	//binding for listen
	LOG_E(THIS_FILE, "tcp_server_thread : ...2\n");
	if ( bind(sockfd, (struct sockaddr*)&my_addr, sizeof(struct sockaddr)) == -1 ){
		exit_val = -1;
		goto tcp_server_thread_end;
	}
 
	LOG_E(THIS_FILE, "tcp_server_thread : ...3 listen port =%d", iPort);
	//Start listening
	if ( listen(sockfd, 8) == -1 ){
		exit_val = -1;
		goto tcp_server_thread_end;
	}
 
	LOG_E(THIS_FILE, "tcp_server_thread : ...4   while\n");
	//Connect
	while(!srv_info->thr_terminate){
	LOG_E(THIS_FILE, "tcp_server_thread : ...5   accept\n");
		if ( (new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &sin_size)) == -1 ){
			LOG_E(THIS_FILE, "accept failed");
			exit_val = -1;
			break;
		}
		// create thread for recieve data
		int		cl_thr_result;
		int		err;
		PCL_THR_INFO pcl_thr_info= malloc(sizeof(CL_THR_INFO));
		pcl_thr_info->server_accept_sock = new_fd;
		LOG_E(THIS_FILE, "tcp_server_thread : ...6   create Client thread newfd=%d", new_fd);
		s = pthread_create(&pcl_thr_info->thread_id, NULL, ClientThread, pcl_thr_info);
		err = pthread_join(pcl_thr_info->thread_id, &cl_thr_result);
		if(pcl_thr_info) {
			free(pcl_thr_info);	
			pcl_thr_info=NULL;
		}
		LOG_E(THIS_FILE, "pthread_join return %d", cl_thr_result);
	}
 
tcp_server_thread_end:	
	LOG_E(THIS_FILE, "tcp_server_thread : ...END\n");
	exit_val = 0;
	pthread_exit(&exit_val);	
	return arg;
}

int start_tcp_server_thread()
{
	int		s;
	void*	res;

//	PSRV_THREAD_INFO pSrv_info = &srv_thr_info;   
	pSrv_info = malloc(sizeof(SRV_THREAD_INFO));
	memset(pSrv_info, 0, sizeof(SRV_THREAD_INFO)); 
	LOG_E(THIS_FILE,"start_tcp_server_thread : create server thread, pSrv_info=%p", pSrv_info);
	s = pthread_create(&pSrv_info->thread_id, NULL, tcp_server_thread, &pSrv_info);
	if (s) {
		LOG_E(THIS_FILE, "create failed");
		goto tcp_server_run_end;
	}
	LOG_E(THIS_FILE,"start_tcp_server_thread : server threadid=%d", pSrv_info->thread_id);
tcp_server_run_end:
	return 0;
}

int stop_tcp_server_thread()
{	
	//PSRV_THREAD_INFO pSrv_info = &srv_thr_info;   
	if(pSrv_info) {
		int srv_thr_result;
		pSrv_info->thr_terminate=1;
		close(pSrv_info->srv_sockfd);
		LOG_E(THIS_FILE, "pthread join ......................wait..");
		pthread_join(pSrv_info->thread_id, &srv_thr_result);
		LOG_E(THIS_FILE, "pthread join ......................result=%d.", srv_thr_result);
		free(pSrv_info);
	}
	return 0;
}

