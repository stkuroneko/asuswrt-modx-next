#include <stdio.h>
#include <unistd.h>
#include <tcp_server.h>
#include <string.h>
#include <unistd.h>	//write()
#include <stdio.h>	//perror()

//#define TEST_CODE 1
char g_device_id[128];
int send_device_id(int send_fd)
{
	if (!send_fd) return -1;
	if (write(send_fd, g_device_id, strlen(g_device_id)) == -1) {
		perror ("write to client error");
		return -1;	 
	}
	return 0;
}

int recv_aicloud_mobile_msg(char* recv_data, int rec_size)
{
	if(rec_size <=0)	return -1;
	if(!recv_data)		return -1;
	if(!strcmp(recv_data, "GET_DEV_ID"))
		return 0;
	else return -1;
}

int start_aicloud_message_srv(char* dev_id)
{
	if (!dev_id) return -1;
	memset(g_device_id, 0, sizeof(g_device_id));
	strlcpy(g_device_id, dev_id, sizeof(g_device_id));
	return start_tcp_server(recv_aicloud_mobile_msg, send_device_id);
}

#if TEST_CODE
int send_test(int s)
{
	return 0;
}

int recv_test(char* recv_data, int rec_size)
{
	printf("*********************** recv size = %d \n", rec_size);
	return 0;	
}

int start_test_srv()
{
   return start_tcp_server(recv_test, send_test);
}
#endif
