#include<stdio.h>

#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <shutils.h>
#include <string.h>
#include <stdlib.h>
#include <bcmnvram.h>

#include <arpa/inet.h>
#include <sys/stat.h>

#include <sys/resource.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>

#include <syslog.h>

#include <net/if.h>


#define MAXDATASIZE 1024
#define BACKLOG 100 /* max listen num*/
#define MYPORT 18020
#define MAXLINE				2048
#define PATHLEN				256
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"

char dst_url[256];

int exit_loop = 0;
void send_page(int wan_unit, int sfd, char *file_dest, char *url)
{
	char buf[2*MAXLINE];
	time_t now;
	char timebuf[100];
	char dut_addr[64];

	memset(buf, 0, sizeof(buf));
	now = uptime();
	(void)strftime(timebuf, sizeof(timebuf), RFC1123FMT, gmtime(&now));

	sprintf(buf, "%s%s%s%s%s%s", buf, "HTTP/1.1 302 Found\r\n", "Server: fb-wifi\r\n", "Date: ", timebuf, "\r\n");

	memset(dut_addr, 0, 64);

		strcpy(dut_addr, nvram_safe_get("lan_ipaddr"));

		//sprintf(buf, "%s%s%s%s%s%s%s", buf, "Connection: close\r\n", "Location:http://", dut_addr, ":18020/fbwifi/forward.asp?u=",url,"\r\nContent-Type: text/plain\r\n\r\n<html></html>\r\n"); 
		sprintf(buf, "%s%s%s%s%s%s%s" ,buf , "Connection: close\r\n", "Location:http://", dut_addr, "/fbwifi/index.asp","\r\nContent-Type: text/plain\r\n", "\r\n<html></html>\r\n");


	fprintf(stderr,"buf:%s\n",buf);
	write(sfd, buf, strlen(buf));
	close(sfd);
}

void parse_dst_url(char *page_src){
	int i, j;
	char dest[PATHLEN], host[64];
	char host_strtitle[7], *hp;
	
	j = 0;
	memset(dest, 0, sizeof(dest));
	memset(host, 0, sizeof(host));
	memset(host_strtitle, 0, sizeof(host_strtitle));
	
	for(i = 0; i < strlen(page_src); ++i){
		if(i >= PATHLEN)
			break;
		
		if(page_src[i] == ' ' || page_src[i] == '?'){
			dest[j] = '\0';
			break;
		}
		
		dest[j++] = page_src[i];
	}
	
	host_strtitle[0] = '\n';
	host_strtitle[1] = 'H';
	host_strtitle[2] = 'o';
	host_strtitle[3] = 's';
	host_strtitle[4] = 't';
	host_strtitle[5] = ':';
	host_strtitle[6] = ' ';
	
	if((hp = strstr(page_src, host_strtitle)) != NULL){
		hp += 7;
		j = 0;
		for(i = 0; i < strlen(hp); ++i){
			if(i >= 64)
				break;
			
			if(hp[i] == '\r' || hp[i] == '\n'){
				host[j] = '\0';
				break;
			}
			
			host[j++] = hp[i];
		}
	}
	
	memset(dst_url, 0, sizeof(dst_url));
	sprintf(dst_url, "%s/%s", host, dest);
}

void handle_http_req(int sfd, char *line,struct sockaddr_in addr)
{
	int len;
	char *ip;
	if(!strncmp(line, "GET /", 5)){

		parse_dst_url(line+5);
		
		len = strlen(dst_url);

		if((line[6] == 'H') &&
				(line[7] == 'T') &&
				(line[8] == 'T') &&
				(line[9] == 'P')){
			ip = inet_ntoa(addr.sin_addr);
		fprintf(stderr,"socket buf = %s\n",line);
		fprintf(stderr,"dst_url = %s\n",dst_url);
		fprintf(stderr,"ip = %s\n",ip);
		
		send_page(0, sfd, NULL, dst_url);
		nvram_set("fbwifi_host",dst_url);
		}
		else
		{
			close(sfd);
			return;
		}
		
	}
	else
		close(sfd);
}
int main()
{
    int sockfd, new_fd; /* listen on sock_fd, new connection on new_fd*/
    int numbytes;
    char buf[MAXDATASIZE];
    int yes = 1;
    int ret;

    fd_set read_fds;
    fd_set master;
    int fdmax;
    struct timeval timeout;

    FD_ZERO(&read_fds);
    FD_ZERO(&master);

    struct sockaddr_in my_addr; /* my address information */
    struct sockaddr_in their_addr; /* connector's address information */
    int sin_size;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
        perror("Server-setsockopt() error lol!");
        exit(1);
    }

    my_addr.sin_family = AF_INET; /* host byte order */
    my_addr.sin_port = htons(MYPORT); /* short, network byte order */
    my_addr.sin_addr.s_addr = INADDR_ANY; /* auto-fill with my IP */
    bzero(&(my_addr.sin_zero), sizeof(my_addr.sin_zero)); /* zero the rest of the struct */

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct
                                                         sockaddr))== -1) {
        perror("bind");
        exit(1);
    }
    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }
    sin_size = sizeof(struct sockaddr_in);

    FD_SET(sockfd,&master);
    fdmax = sockfd;

    while(!exit_loop)
    { /* main accept() loop */

        timeout.tv_sec = 0;
        timeout.tv_usec = 100;

        read_fds = master;

        ret = select(fdmax+1,&read_fds,NULL,NULL,&timeout);

        switch (ret)
        {
        case 0:
            //printf("No data in ten seconds\n");
            continue;
            break;
        case -1:
            perror("select");
            continue;
            break;
        default:
            if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr, \
                                 &sin_size)) == -1) {
                perror("accept");
                continue;
            }
            memset(buf, 0, sizeof(buf));

            if ((numbytes=recv(new_fd, buf, MAXDATASIZE, 0)) == -1) {
                perror("recv");
				if(errno != EINTR && errno != EAGAIN)
					close(new_fd);
                continue;
            }

            if(buf[strlen(buf)] == '\n')
            {
                buf[strlen(buf)] = '\0';
            }
            //fprintf(stderr,"socket buf = %s\n",buf);
			handle_http_req(new_fd, buf,their_addr);
            //close(new_fd);
        }

    }
    close(sockfd);

    fprintf(stderr,"stop  fb-wifi\n");


}
