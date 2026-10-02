/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2012, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <amas_ssd.h>
#include <amas_wlcconnect.h>
#if !defined(__GLIBC__) && !defined(__UCLIBC__) /* musl */
#include <poll.h>
#else
#include <sys/poll.h>
#endif
#include <amas_ipc.h>


#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#define AMAS_IPC_DBG_LOG    "amas_ipc.log"
#define IPC_DBG(fmt, arg...) \
	do {    \
		if(!strcmp(nvram_safe_get("amasipc_dbg"), "1")) \
			dbG("WLC %lu: "fmt, uptime(), ##arg); \
		if (!strcmp(nvram_safe_get("amasipc_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_IPC_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)
#else
#define IPC_DBG(fmt, arg...) \
        do {    \
               if(!strcmp(nvram_safe_get("amasipc_dbg"), "1")) \
                dbG("IPC %lu: "fmt, uptime(), ##arg); \
            	if (!strcmp(nvram_safe_get("amasipc_syslog"), "1")) \
					logmessage("IPC", fmt, ##arg); \
        } while (0)
#endif

/**
 * @brief Close IPC socket
 *
 * @param fd Socket file descriptor
 */
void close_ipc(int fd)
{
    if (fd >= 0) {
        IPC_DBG("Close IPC socket. fd:%d\n", fd);
        close(fd);
    }
}

/**
 * @brief Create socket and connect to remote server
 *
 * @param ipc_socket_path IPC socket path
 * @return int Connect to remote server result
 *      > 0: File descriptor number
 *      <= -1: Connect error
 */
int connect_ipc(char *ipc_socket_path)
{
    int fd = -1;
	struct sockaddr_un addr;
    int flags, ret;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        IPC_DBG("ipc socket error! %s\n", strerror(errno));
        goto CONNECT_IPC_ERR;
    }

    if (fd != -1) {

        flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags|O_NONBLOCK); // Setting nonblock mode.

	    memset(&addr, 0, sizeof(addr));
	    addr.sun_family = AF_UNIX;
	    strncpy(addr.sun_path, ipc_socket_path, sizeof(addr.sun_path)-1);
        ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret == 0) // Success.
            return fd;
        else {
            if (errno == EINPROGRESS) { // Still doing IPC connection process.
                int connect_timeout = 5; // 5 times for connect()
                while (connect_timeout-- > 0) {
                    fd_set rfds, wfds;
                    struct timeval tv;

                    FD_ZERO(&rfds);
                    FD_ZERO(&wfds);
                    FD_SET(fd, &rfds);
                    FD_SET(fd, &wfds);

                    tv.tv_sec = 10; // select time out 10sec
                    tv.tv_usec = 0;
                    int selret = select(fd + 1, &rfds, &wfds, NULL, &tv);
                    switch (selret) {
                        case -1 : // select error
                            goto CONNECT_IPC_ERR;
                        case 0 : // select timeout
                            goto CONNECT_IPC_ERR;
                        default:
                            if (FD_ISSET(fd, &rfds) || FD_ISSET(fd, &wfds)) {
                                ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
                                if (errno == EISCONN) {
                                    ret = 0; // Success
                                }
                                else
                                    ret = errno;
                            }
                            else
                                continue;
                    }
                    if (ret == 0) // Success.
                        break;
                }
                if (ret != 0)
                    goto CONNECT_IPC_ERR;
            }
            else {
                IPC_DBG("ipc connect error! %s\n", strerror(errno));
                goto CONNECT_IPC_ERR;
            }
	    }
    }
    return fd;

CONNECT_IPC_ERR:
    close_ipc(fd);
    return -1;
}

/**
 * @brief Read message from IPC socket
 *
 * @param fd Socket file descriptor
 * @param msg Messages from IPC
 * @param msg_max_len Max length of message
 * @param timeout Reading socket timeout. The time unit is millisecond
 * @return int Reading socket result
 *      0: Read successfully
 *      -1: Read error
 */
int read_ipc_msg(int fd, char *msg, int msg_max_len, int timeout)
{
    int ret, nleft, nread, len = 0;
    char *pMsg;
    struct pollfd monitor_fd;

    if (fd < 0) {
        IPC_DBG("Socket description error.fd = %d\n", fd);
        goto READ_IPC_EVENT_ERROR;
    }

    monitor_fd.fd = fd;
    monitor_fd.events = POLLIN;

    ret = poll(&monitor_fd, 1, timeout);

    if (ret == -1) {
        IPC_DBG("Poll socket error! %s\n", strerror(errno));
        goto READ_IPC_EVENT_ERROR;
    }
    else if (ret == 0) {
        IPC_DBG("Read Socket timeout! %d\n", strerror(errno));
        goto READ_IPC_EVENT_ERROR;
    }
    else {
        if (monitor_fd.revents & POLLIN) {
            nleft = msg_max_len;
            pMsg = msg;

            while (nleft > 0) {
                if ( (nread = read(fd, msg, nleft)) < 0) {
                    if (errno == EINTR) {
                        nread = 0;  /* and call read() again */
                        IPC_DBG("errno == EINTR\n");
                    }
                    else {
                        IPC_DBG("Failed to socket read(%d)!\n", errno);
                        goto READ_IPC_EVENT_ERROR;
                    }
                } else if (nread == 0) {
                    IPC_DBG("EOF, data received len(%d)\n", len);
                    break;    /* EOF */
                }
                nleft -= nread;
                pMsg += nread;
                len += nread;

                IPC_DBG("Total received len(%d)\n", len);
                if (len > msg_max_len) {
                    IPC_DBG("Total received len(%d) > msssage max len(%d)\n", len, msg_max_len);
                    goto READ_IPC_EVENT_ERROR;
                }
            }
            IPC_DBG("Read msg: %s\n", msg);
        }
        else {
            IPC_DBG("Poll socket exception revents 0x%x!\n", monitor_fd.revents);
            goto READ_IPC_EVENT_ERROR;
        }
    }

    return 0;

READ_IPC_EVENT_ERROR:
    return -1;
}

/**
 * @brief Send message to IPC socket
 *
 * @param fd Socket file descriptor
 * @param msg Messages are be sent
 * @param timeout Sending socket timeout. The time unit is millisecond
 * @return int Sending socket result
 *      0: Send successfully
 *      -1: Send error
 */
int send_ipc_msg(int fd, char *msg, int timeout) // timeout millisecond.
{
	if (strlen(msg) == 0) {
		IPC_DBG("the size of msg is equal to 0\n");
		goto SEND_IPC_EVENT_ERROR;
	}

    int length, ret;
    struct pollfd monitor_fd;
    monitor_fd.fd = fd;
    monitor_fd.events = POLLOUT;

    ret = poll(&monitor_fd, 1, timeout);

    if (ret == -1) {
        IPC_DBG("Poll socket error! %s\n", strerror(errno));
        goto SEND_IPC_EVENT_ERROR;
    }
    else if (ret == 0) {
        IPC_DBG("Write Socket timeout! %d\n", strerror(errno));
        goto SEND_IPC_EVENT_ERROR;
    }
    else {
        if (monitor_fd.revents & POLLOUT) {
            IPC_DBG("Write msg: %s\n", msg);
	        length = write(fd, msg, AMAS_IPC_MSG_SIZE);
	        if (length < 0) {
        		IPC_DBG("Writing Socket error! %s\n", strerror(errno));
		        goto SEND_IPC_EVENT_ERROR;
	        }
        }
        else {
            IPC_DBG("Poll socket exception revents 0x%x!\n", monitor_fd.revents);
            goto SEND_IPC_EVENT_ERROR;
        }
    }

    return 0;

SEND_IPC_EVENT_ERROR:
    return -1;
}

/**
 * @brief Send a message to remote server and receive a message from remote server
 *
 * @param ipc_socket_path IPC socket path
 * @param msg Message will be sent
 * @param rsp_msg Messages will be received
 * @param rsp_msg_max_len Max length of respond message
 * @param timeout Sending message and receiving message time out. The time unit is millisecond
 * @return int Send message and receive response message result
 *      0: Success
 *      -1: Error
 */
int send_msg_to_ipc_socket(char *ipc_socket_path, char *msg, char *rsp_msg, int rsp_msg_max_len, int timeout)
{
	int fd = -1;
	int ret = -1;

	if (strlen(msg) == 0) {
		IPC_DBG("the size of msg is equal to 0\n");
        goto SEND_MSG_ERROR;
	}

    fd = connect_ipc(ipc_socket_path);
    if (fd == -1) {
        IPC_DBG("Connect to %s\n", ipc_socket_path);
        goto SEND_MSG_ERROR;
    }

    ret = send_ipc_msg(fd, msg, timeout);
    if (ret) {
        IPC_DBG("Send msg error\n");
        goto SEND_MSG_ERROR;
    }

    ret = read_ipc_msg(fd, rsp_msg, rsp_msg_max_len, timeout);
    if (ret) {
        IPC_DBG("Read msg error\n");
        goto SEND_MSG_ERROR;
    }
    IPC_DBG("Response msg: %s\n", rsp_msg);

	ret = 0;

SEND_MSG_ERROR:
    close_ipc(fd);
	return ret;
}

/**
 * @brief Read a message from remote server and send a message to remote server
 *
 * @param fd Socket file descriptor
 * @param msg Messages will be received
 * @param msg_max_len Max length of message
 * @param rsp_msg Response message will be sent
 * @param timeout Sending message and receiving message time out. The time unit is millisecond
 * @return int Receive message and send response message result
 *      0: Success
 *      -1: Error
 */
int read_msg_from_ipc_socket(int fd, char *msg, int msg_max_len, char *rsp_msg, int timeout)
{
	int ret = -1;

	if (strlen(rsp_msg) == 0) {
		IPC_DBG("the size of response_msg is equal to 0\n");
        goto READ_MSG_ERROR;
	}

    ret = read_ipc_msg(fd, msg, msg_max_len, timeout);
    if (ret) {
        IPC_DBG("Read msg error\n");
        goto READ_MSG_ERROR;
    }
    IPC_DBG("Read msg: %s\n", msg);

    ret = send_ipc_msg(fd, rsp_msg, timeout);
    if (ret) {
        IPC_DBG("Send response msg error\n");
        goto READ_MSG_ERROR;
    }
	ret = 0;

READ_MSG_ERROR:
    close_ipc(fd);
	return ret;
}

/**
 * @brief Show the amas_ipc test useage
 *
 */
void usage_help()
{
	dbg("\nUsage: amas_ipc [OPTION]...\n\n"
			"Options:\n"
            "\t\t -m \t Set ipc test mode. (1: amas_ssd 2: amas_wlcconnect) \n"
			"\t\t -p \t Set ipc socket path\n"
			"\t\t -u \t Set band unit (0, 1, 2)\n"
			"\t\t -s \t Set ssid list (XXX,YYY)\n"
			"\t\t -e \t Set Event string (Only mode:2)\n"
			"\t\t -h \t Display this help\n");
	exit(1);
}

/**
 * @brief Main function
 *
 * @param argc argument counter
 * @param argv argument vector
 * @return int The process exit state
 */
int amas_ipc_main(int argc, char *argv[])
{
	char msg[AMAS_IPC_MSG_SIZE], ssid_list[AMAS_IPC_MSG_SIZE], rsp_msg[AMAS_IPC_MSG_SIZE] = {};
	int c, unit = -1, mode = 0;
	char *ipc_socket_path = NULL;
	char *ssid_list_str = NULL, *str, *ptr, *event_str = NULL;
	int first_update = 0, ret = -1, event = 0;

	if (argc < 3){
		usage_help();
	}

	while((c = getopt(argc, argv, "m:p:u:s:e:h")) != -1){
		switch(c){
            case 'm':
                mode = strtod(optarg, NULL);
                dbg("Test mode is %d\n", mode);
                break;
			case 'p':
				ipc_socket_path = optarg;
				dbg("ipc socket path = %s.\n", ipc_socket_path);
				break;
			case 'u':
				unit = strtod(optarg, NULL);
				dbg("band unit = %d.\n", unit);
				break;
			case 's':
				ssid_list_str = optarg;
				dbg("ssid list = %s.\n", ssid_list_str);
				break;
			case 'e':
                if (mode == 2) {
                    event_str = optarg;
                    dbg("event = %s.\n", event_str);
                }
                else {
				    event= strtod(optarg, NULL);
				    dbg("event = %d.\n", event);
                }
				break;
			case 'h':
				usage_help();
				break;
			default:
				dbg("Invalid parameters: '%c'", c);
				usage_help();
		}
	}

    if (mode == 1) {
        if (event == 0 || unit == -1)
            usage_help();
        else if (event == SS_EVENT_START) {
		    /* convert ssid_list_str to ssid_list format (["XXX","YYY"]) */
		    memset(ssid_list, 0, sizeof(ssid_list));
		    strlcat(ssid_list, "[", sizeof(ssid_list));
		    for (str = ssid_list_str; str != NULL; str = ptr) {
    			if ((ptr = strchr(str, ',')) != NULL)
				    *ptr++ = '\0';

			    if (strlen(str)) {
    				if (!first_update)
					    first_update = 1;
				    else
    					strlcat(ssid_list, ",", sizeof(ssid_list));
				    strlcat(ssid_list, "\"", sizeof(ssid_list));
				    strlcat(ssid_list, str, sizeof(ssid_list));
				    strlcat(ssid_list, "\"", sizeof(ssid_list));
			    }
		    }
		    strlcat(ssid_list, "]", sizeof(ssid_list));
		    snprintf(msg, sizeof(msg), SSD_START_EVENT_MSG, unit, ssid_list);
	    }
	    else if (event == SS_EVENT_CANCEL) {
    		snprintf(msg, sizeof(msg), SSD_CANCEL_EVENT_MSG, unit);
    	}
        if (strlen(msg) > 0)
	        ret = send_msg_to_ipc_socket(AMAS_SSD_IPC_SOCKET_PATH, &msg[0], rsp_msg, AMAS_IPC_MSG_SIZE, 3000);
    }
    else if (mode == 2) {
        snprintf(msg, sizeof(msg), "%s", event_str);
        ret = send_msg_to_ipc_socket(AMAS_WLCCONNECT_IPC_SOCKET_PATH, &msg[0], rsp_msg, AMAS_IPC_MSG_SIZE, 3000);
    }
    else {
        dbg("mode %d invalid. Please setting valid mode.\n", mode);
        usage_help();
        return 0;
    }

    if (!ret) {
        if (strlen(rsp_msg) > 0)
            dbg("IPC: Get response msg: %s\n", rsp_msg);
        else
            dbg("IPC: Doesn't get response.\n");
    }
    else {
        dbg("Send msg to IPC socket fail.\n");
    }

    return 0;
}
