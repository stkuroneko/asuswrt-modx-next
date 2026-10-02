/*
 * Project: asusnatnl
 * File: im_handler.c
 *
 * Copyright (C) 2014 ASUSTek
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
// We will rewrite our own pjsua in future
#include <im_handler.h>
#include <socket.h>
#include <natnl_event.h>
#include <time.h>
#include <list.h>
#include <client.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <pthread.h>
#else
#include "helpers/winhelpers.h"
#endif

#define THIS_FILE "im_handler.c"

extern int debug_level;
extern int ipver;
extern PJ_DEF(pj_pool_t *) pjsip_get_app_pool(int inst_id);
extern PJ_DEF(void *) natnl_get_im_lport_socks(int inst_id);
extern PJ_DEF(void)   natnl_set_im_lport_socks(int inst_id, natnl_list_t *im_lport_socks);
extern PJ_DEF(void *) natnl_get_im_sessions(int inst_id);
extern PJ_DEF(void)   natnl_set_im_sessions(int inst_id, natnl_list_t *im_sessions);
extern void disconnect_and_remove_client(client_t *c, natnl_list_t *clients,
										 fd_set *fds, int full_disconnect, int type);
extern PJ_DEF(char *) natnl_get_curr_sip_srv(int inst_id);
extern PJ_DEF(void *) natnl_get_im_lport_thread(int inst_id);
extern PJ_DEF(void) natnl_set_im_lport_thread(int inst_id, pj_thread_t *thread);
extern PJ_DEF(void *) natnl_get_im_lock(int inst_id);
extern PJ_DEF(void) natnl_set_im_lock(int inst_id, pj_mutex_t *lock);
extern PJ_DEF(pj_bool_t) natnl_get_im_lport_thread_quit(int inst_id);
extern PJ_DEF(void) natnl_set_im_lport_thread_quit(int inst_id, pj_bool_t quit);
static uint16_t next_req_id = 1;
int im_lport_thread(void *arg);

/*
 * return 0 : success                                                   
 *       -1 : connect failed                                             
 *       -2 : connection reset by peer
 *       -3 : connection closed by peer normally
 *       -4 : read timeout
 */
int send_im(struct natnl_im_data *im_data, int wait_timeout_sec) {
	socket_t *sock;
	char rport[6];
	int error_code = 0;
	int status;
	int ret;
	fd_set read_fds;
	struct timeval timeout;
	int num_fds;

	// prepare rport string
	memset(rport, 0, sizeof(rport));
	sprintf(rport, "%d", im_data->rport);

	PJ_LOG(4, (THIS_FILE, "send_im 1"));
	// create socket and connect to loopback:rport
	status = -1;
	error_code = sock_create(&sock, "127.0.0.1", rport, NULL, 0, SOCK_IPV4, 
		                     SOCK_TYPE_TCP, 0, 1, 0, 0, 0, im_data->inst_id, -1);
	PJ_LOG(4, (THIS_FILE, "send_im 2"));
	//ERROR_GOTO(THIS_FILE, sock == NULL, "Error creating TCP socket.", done);
	if (sock == NULL) {
		PJ_PERROR_GOTO(1, done, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
			"[%d/%d/?] send_im() Failed to create sock.", 
			im_data->inst_id, -1));
	}

	/*ret = sock_send(sock, (char *)&im_data->rdata->msg_info.msg->body->len, sizeof(int));

	if(ret < 0)
		return -2;
	else if(ret == 0)
		return -3;*/

	PJ_LOG(4, (THIS_FILE, "send_im 3"));
	PJ_LOG(4, (THIS_FILE, "send_im 3 r_msg=[%p]", im_data->r_msg));
	PJ_LOG(4, (THIS_FILE, "send_im 3 rdata=[%p]", im_data->rdata));
	PJ_LOG(4, (THIS_FILE, "send_im 3 msg=[%p]", im_data->rdata->msg_info.msg));
	PJ_LOG(4, (THIS_FILE, "send_im 3 body=[%p]", im_data->rdata->msg_info.msg->body));
	//if (im_data->r_msg && im_data->r_msg->slen)
	//	ret = sock_send(sock, (char *)im_data->r_msg->ptr, im_data->r_msg->slen);
	ret = sock_send(sock, (char *)im_data->rdata->msg_info.msg->body->data, im_data->rdata->msg_info.msg->body->len);

	PJ_LOG(4, (THIS_FILE, "send_im 4 sent_size=[%d]", ret));
	if(ret < 0) {
		status = -2;
		goto done;
	} else if(ret == 0) {
		status = -3;
		goto done;
	}

	FD_ZERO(&read_fds);
	if(!FD_ISSET(SOCK_FD(sock), &read_fds))
		FD_SET(SOCK_FD(sock), &read_fds);

	timerclear(&timeout);
	timeout.tv_sec = wait_timeout_sec;
	timeout.tv_usec = 0;
	PJ_LOG(4, (THIS_FILE, "send_im 5"));
	num_fds = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout);

	if (num_fds > 0 && FD_ISSET(SOCK_FD(sock), &read_fds)) {
		int data_len;
		char *buffer;

		// receive data_len
		/*ret = sock_recv(sock, NULL, (char *)&data_len, sizeof(int));

		if(ret < 0)
			return -2;
		else if(ret == 0)
			return -3;*/
		
		//im_data->result_body.ptr = (char *)malloc(data_len);
		memset(im_data->result_body, 0, sizeof(im_data->result_body));
		PJ_LOG(4, (THIS_FILE, "send_im 6"));
		// receive data
		ret = sock_recv_whole_data(sock, NULL, (char *)im_data->result_body, sizeof(im_data->result_body));

		PJ_LOG(4, (THIS_FILE, "send_im 7 ret=[%d]", ret));
		if(ret < 0) {
			status = -4;
			goto done;
		} else if(ret == 0) {
			status = -5;
			goto done;
		}

		//im_data->result_body.slen = data_len;

		status = 0;
		goto done;

	} else {
		status = -6;
		goto done;
	}

	PJ_LOG(4, (THIS_FILE, "send_im 8"));

done:
	sock_close(sock);
	return status;
}

int im_handler_thread(void *arg) {
        struct natnl_im_data *im_data = (struct natnl_im_data *)arg;
        int ret = 0;
        int st_code;
        pjsip_msg_body *result_msg_body = NULL;
        pjsip_media_type media_type;

        const pj_str_t mime_text_plain = pj_str("text/plain");

        memset(&im_data->result_body, 0, sizeof(im_data->result_body));
#if 1
        // send instant message to loopback:rport and wait result.
#if 1
        ret = send_im(im_data, im_data->timeout_sec);
#else
        im_data->result_body.ptr = "OK";
        im_data->result_body.slen = 2;
#endif

        if (ret < 0)
            st_code = 408;
        else {
			pj_str_t result = pj_str(im_data->result_body);
            st_code = 200;
            // Parse MIME type
            pjsua_parse_media_type(pjsua_var[im_data->inst_id].pool, &mime_text_plain, &media_type);

            // create sip message body
            result_msg_body = pjsip_msg_body_create(pjsua_var[im_data->inst_id].pool, &media_type.type,
                    &media_type.subtype,
                    &result);
        }
#else
        snprintf(im_data->result_body, sizeof(im_data->result_body), "OK");
        pj_str_t result = pj_str(im_data->result_body);
        st_code = 200;
        // Parse MIME type
        pjsua_parse_media_type(pjsua_var[im_data->inst_id].pool, &mime_text_plain, &media_type);
        result_msg_body = pjsip_msg_body_create(pjsua_var[im_data->inst_id].pool, &media_type.type,
                &media_type.subtype,
                &result);
#endif
#if 0
        // send the result back
        pjsip_endpt_respond(pjsua_var[im_data->inst_id].endpt, NULL, im_data->rdata, st_code, NULL,
                NULL, result_msg_body, NULL);
#else
        // send the result back
        pjsip_endpt_respond_stateless(pjsua_var[im_data->inst_id].endpt, im_data->rdata, st_code, NULL,
                NULL, result_msg_body);
#endif
        /*if (im_data->result_body.ptr) {
                free(im_data->result_body.ptr);
                im_data->result_body.slen = 0;
        }*/
        pj_bzero(&im_data->rdata->endpt_info, sizeof(im_data->rdata->endpt_info));
		if (im_data->r_msg) {
			if (im_data->r_msg->ptr) {
				free(im_data->r_msg->ptr);
				im_data->r_msg->ptr = NULL;
			}
			free(im_data->r_msg);
			im_data->r_msg = NULL;
		}
		if (im_data->proc_name) {
			free(im_data->proc_name);
			im_data->proc_name = NULL;
		}
        return 0;
}

int im_init(int inst_id) {

	natnl_list_t *im_lport_socks = (natnl_list_t *)natnl_get_im_lport_socks(inst_id);
	natnl_list_t *im_sessions = (natnl_list_t *)natnl_get_im_sessions(inst_id);
	pj_mutex_t *lock = (pj_mutex_t *)natnl_get_im_lock(inst_id);

	if (!im_lport_socks) {
		im_lport_socks = natnl_list_create(inst_id, -1, sizeof(socket_t), NULL, NULL, p_socket_t_free, 0);
		natnl_set_im_lport_socks(inst_id, im_lport_socks);
	}

	if (!im_sessions) {
		im_sessions = natnl_list_create(inst_id, -1, sizeof(client_t), p_client_cmp, p_client_copy,
			p_client_free, 0);
		natnl_set_im_sessions(inst_id, im_sessions);
	}

	if (!lock) {
		int status = pj_mutex_create_simple(pjsip_get_app_pool(inst_id), NULL, &lock);
		if (status != PJ_SUCCESS) {
			return status;
		}

		natnl_set_im_lock(inst_id, lock);
	}

	return 0;
}

int im_destroy(int inst_id) {

	natnl_list_t *im_lport_socks = (natnl_list_t *)natnl_get_im_lport_socks(inst_id);
	natnl_list_t *im_sessions = (natnl_list_t *)natnl_get_im_sessions(inst_id);
	pj_mutex_t *lock = (pj_mutex_t *)natnl_get_im_lock(inst_id);
	
	natnl_set_im_lport_thread_quit(inst_id, PJ_TRUE);

	if (lock)
		pj_mutex_lock(lock);
	
	if (im_lport_socks) {
		natnl_list_free(&im_lport_socks);
		natnl_set_im_lport_socks(inst_id, NULL);
	}

	if (im_sessions) {
		natnl_list_free(&im_sessions);
		natnl_set_im_sessions(inst_id, NULL);
	}

	if (lock) {
		pj_mutex_unlock(lock);
		pj_mutex_destroy(lock);
		natnl_set_im_lock(inst_id, lock);
	}

	return 0;
}

int im_srv_socket_init(int inst_id, 
					   char *des_device_id, 
					   char *lport, 
					   char *rip,
					   char *rport,
					   int timeout_sec) {
	char addrstr[ADDRSTRLEN];
	int status;
	int error_code = 0;
	char *lhost;
	socket_t *tcp_serv = NULL, *tcp_serv2 = NULL;
	int i;
	char tmp_lport[6];
	pj_thread_t *thread;

	natnl_list_t *im_lport_socks = (natnl_list_t *)natnl_get_im_lport_socks(inst_id);
	pj_mutex_t *lock = (pj_mutex_t *)natnl_get_im_lock(inst_id);

	if (lock)
		pj_mutex_lock(lock);

	if (!im_lport_socks) {
		im_lport_socks = natnl_list_create(inst_id, -1, sizeof(socket_t), NULL, NULL, p_socket_t_free, 0);
		natnl_set_im_lport_socks(inst_id, im_lport_socks);
	}

	// DEAN, check if lport is already created. if so return error.
	if(im_lport_socks) {
		for (i = 0; i < LIST_LEN(im_lport_socks); i++)
		{
			tcp_serv = (socket_t *)natnl_list_get_at(im_lport_socks, i);

			sprintf(tmp_lport, "%d", tcp_serv->lport);
			if (tcp_serv && 
				strcmp(tmp_lport, lport) == 0)
			{
				if (lock)
					pj_mutex_unlock(lock);
				return (natnl_status_code)PJ_EEXISTS;
			}
		}
	}

	/* Create a TCP server socket to listen for incoming connections */
	lhost = NULL;
	PJ_LOG(4, (THIS_FILE, "[%d/?] im_srv_socket_init() init looback server for [127.0.0.1:%s] to [remote:%s]", 
		inst_id, lport, rport));

	//DEAN loopback tcp server
	status = NATNL_SC_TNL_CREATE_SOCK_FAILED;
	error_code = sock_create(&tcp_serv, lhost, lport, rip, rport, 
		ipver, SOCK_TYPE_TCP, 1, 1, 0, 0, 0, inst_id, 0);
	//ERROR_GOTO(THIS_FILE, tcp_serv == NULL, "Error creating TCP socket.", done);
	if (tcp_serv == NULL) {
		PJ_PERROR_GOTO(1, done, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
			"[%d/?] im_srv_socket_init() [%s] socket create for [127.0.0.1:%s] failed. err=[%d]", 
			inst_id, "TCP", lport, error_code));
	}

	strcpy(tcp_serv->im_dest_deviceid, des_device_id); // destination device id
	tcp_serv->im_timeout_sec = timeout_sec;
	PJ_LOG(4, (THIS_FILE, "[%d/?] im_srv_socket_init() Listening on TCP %s, tcp_serv->fd=[%d]", 
		inst_id, sock_get_str(tcp_serv, addrstr, sizeof(addrstr)), tcp_serv->fd));

	error_code = 0;
	status = NATNL_SC_TNL_ADD_OBJECT_FAILED;
	tcp_serv2 = (socket_t *)natnl_list_add(im_lport_socks, tcp_serv, 1);
	sock_free(&tcp_serv); //No need to close socket fd here.
	//ERROR_GOTO(THIS_FILE, tcp_serv2 == NULL, "Error add TCP socket to list.", done);
	if (tcp_serv2 == NULL) {
		PJ_PERROR_GOTO(1, done, (THIS_FILE, status, 
			"[%d/?] im_srv_socket_init() [%s] Failed to add TCP scoket to list [127.0.0.1:%s].", 
			inst_id, "TCP", lport));
	}

	if (natnl_get_im_lport_thread(inst_id) == NULL) {
		int *arg = (int *)malloc(sizeof(int));
		*arg = inst_id;
		status = pj_thread_create(pjsua_var[inst_id].pool, "im_lport_thread", &im_lport_thread,  
			(void *)arg, 0, 0,
			&thread);
		if (status == PJ_SUCCESS) {
			natnl_set_im_lport_thread(inst_id, thread);

		} else {
			PJ_LOG(4, (THIS_FILE, "[%d/?] im_srv_socket_init() create thread failed on TCP %s, tcp_serv->fd=[%d]", 
				inst_id, sock_get_str(tcp_serv, addrstr, sizeof(addrstr)), tcp_serv->fd));
		}
	}

#if 0
	//DEAN loopback udp server
	status = NATNL_SC_TNL_CREATE_SOCK_FAILED;
	error_code = sock_create(&tcp_serv, lhost, lport, rip, rport, 
		ipver, SOCK_TYPE_UDP, 1, 1, 0, 0, 0, inst_id, 0);
	//ERROR_GOTO(THIS_FILE, tcp_serv == NULL, "Error creating TCP socket.", done);
	if (tcp_serv == NULL) {
		PJ_PERROR_GOTO(1, done, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
			"[%d/?] im_srv_socket_init() [%s] socket create for [127.0.0.1:%s] failed. err=[%d]", 
			inst_id, "UDP", lport, error_code));
	}

	PJ_LOG(4, (THIS_FILE, "[%d/?] im_srv_socket_init() Binding on UDP %s, tcp_serv->fd=[%d]", 
		inst_id, sock_get_str(tcp_serv, addrstr, sizeof(addrstr)), tcp_serv->fd));

	error_code = 0;
	status = NATNL_SC_TNL_ADD_OBJECT_FAILED;
	tcp_serv2 = (socket_t *)list_add(im_lport_socks, tcp_serv, 1);
	sock_free(&tcp_serv); //No need to close socket fd here.
	//ERROR_GOTO(THIS_FILE, tcp_serv2 == NULL, "Error add TCP socket to list.", done);
	if (tcp_serv2 == NULL) {
		error_code = pj_get_native_netos_error();
		PJ_PERROR_GOTO(1, done, (THIS_FILE, status, 
			"[%d/?] im_srv_socket_init() [%s] Failed to add UDP scoket to list [127.0.0.1:%s].", 
			inst_id, "UDP", lport));
	}
#endif
	if (lock)
		pj_mutex_unlock(lock);
	return 0;

done:
	if (lock)
		pj_mutex_unlock(lock);

	return status;
}

int im_srv_socket_destroy(int inst_id, char *lport, char *rport)
{
	int i;
	socket_t *tcp_serv = NULL;
	natnl_list_t *im_lport_socks = (natnl_list_t *)natnl_get_im_lport_socks(inst_id);
	pj_mutex_t *lock;
	char tmp_lport[6], tmp_rport[6];

	if(im_lport_socks) {

		lock = (pj_mutex_t *)natnl_get_im_lock(inst_id);
		if (lock)
			pj_mutex_lock(lock);
		for (i = 0; i < LIST_LEN(im_lport_socks); i++)
		{
			tcp_serv = (socket_t *)natnl_list_get_at(im_lport_socks, i);

			sprintf(tmp_lport, "%d", tcp_serv->lport);
			sprintf(tmp_rport, "%d", tcp_serv->rport);
			if (tcp_serv && 
				strcmp(tmp_lport, lport) == 0 &&
				strcmp(tmp_rport, rport) == 0)
			{
				sock_close(tcp_serv);
				//sock_free(tcp_serv);
				natnl_list_delete(im_lport_socks, tcp_serv);
				PJ_LOG(4, (THIS_FILE, "im_srv_socket_destroy() close sock."));
			}
		}
		if (lock)
			pj_mutex_unlock(lock);
	}
	return 0;
}

int im_recv_resp_msg(void *user_data, pjsip_rx_data *rdata, int status) {
	client_t *session = (client_t *)user_data;
	if ((status == PJ_SC_OK || status == PJ_SUCCESS) && session && rdata) {
		if (session_is_status(session, IM_SESSION_STATUS_REQUEST_SENT)) {
			char *resp = (rdata->msg_info.msg->body ? (char *)rdata->msg_info.msg->body->data : NULL);
			int resp_len = (rdata->msg_info.msg->body ? rdata->msg_info.msg->body->len : 0);
			int buf_size = NATNL_IM_MAX_LEN;
			if (!session->im_res_buf)
				session->im_res_buf = (char*)malloc(buf_size);
			memset(session->im_res_buf, 0, buf_size);
			memcpy(session->im_res_buf, resp, (buf_size > resp_len)?resp_len:buf_size);
			session->im_res_len = resp_len;

			PJ_LOG(4, (THIS_FILE, "im_recv_resp_msg() Got response instant message = [%.*s]", session->im_res_len, session->udp2tcp));
			session_set_status(session, IM_SESSION_STATUS_RESPONSE_GOT);
		} else {
			session_set_status(session, IM_SESSION_STATUS_DESTROYING);
		}
	} else if (status != PJ_SC_OK && status != PJ_SUCCESS && session) {
		session_set_status(session, IM_SESSION_STATUS_DESTROYING);
	}
	return 0;
}

int im_lport_thread(void *arg) {
	int i, num_fds, ret;
	int inst_id = *((int *)arg);
	socket_t *sock;
	struct timeval timeout;
	fd_set read_fds = {0};
	client_t *session = NULL;
	client_t *session2;
	socket_t *in_sock = NULL;
	char *rhost = "127.0.0.1";
	char rport[6];

#ifndef WIN32
	pthread_detach(pthread_self());
#endif

	natnl_list_t *im_lport_socks = (natnl_list_t *)natnl_get_im_lport_socks(inst_id);
	natnl_list_t *im_sessions = (natnl_list_t *)natnl_get_im_sessions(inst_id);
	
	while(!natnl_get_im_lport_thread_quit(inst_id) && LIST_LEN(im_lport_socks) > 0) {
		timerclear(&timeout);
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;
		pj_mutex_t *lock = (pj_mutex_t *)natnl_get_im_lock(inst_id);

		if (lock)
			pj_mutex_lock(lock);

		pj_thread_sleep(1);

		/* Reset the file desc. set */
		for(i = 0; i < LIST_LEN(im_lport_socks); i++) {
			sock = (socket_t *)natnl_list_get_at(im_lport_socks, i);
			if (!sock)
				continue;

			if(!FD_ISSET(SOCK_FD(sock), &read_fds)) {
				uint16_t port;
				int nfds = natnl_get_im_nfds(inst_id);
				natnl_set_im_nfds(inst_id, my_max(nfds, SOCK_FD(sock)));
				FD_SET(SOCK_FD(sock), &read_fds);
				port = sock_get_port(sock);
				PJ_LOG(6, (THIS_FILE, "LOG FD_SET sock_type=%d, dst_port=%d, fd=%d, max_nfds=%d", sock->type, port, SOCK_FD(sock), natnl_get_im_nfds(inst_id)));
			}
		}

//#if defined(PJ_CONFIG_IPHONE) && (PJ_CONFIG_IPHONE != 0)
		num_fds = select(natnl_get_im_nfds(inst_id)+1, &read_fds, NULL, NULL, &timeout);
		// 2013-11-05 DEAN, recover accept operation.
		/* Check if pending TCP connection to accept and create a new client
		   and UDP connection if one is ready */
		for(i = 0; i < LIST_LEN(im_lport_socks); i++) {
			socket_t src_sock;
			int is_first_udp_packet = 0;
			sock = (socket_t *)natnl_list_get_at(im_lport_socks, i);
			if (!sock)
				continue;

			//tp = (pjmedia_transport *)pjsua_get_media_transport(inst_id, call_id);

			/* Check if pending TCP connection to accept and create a new client
			   and UDP connection if one is ready */
			if(FD_ISSET(SOCK_FD(sock), &read_fds)) {
				PJ_LOG(4, (THIS_FILE, "im_lport_thread() cd->tcp_serv is pending."));

				sprintf(rport, "%u", sock->rport);
				if (sock->type == SOCK_STREAM) // DEAN, for loopback tcp connection.
				{
					in_sock = sock_accept(sock);
					if(in_sock == NULL) {
						PJ_LOG(1, (THIS_FILE, "im_lport_thread() sock_accept tcp_sock is null."));					
						continue;
					}
				}
#if 0
				else if (sock->type == SOCK_DGRAM)// DEAN, for loopback udp connection.
				{
					char addr_str[20];
					uint16_t src_port;

					if (cd->udp_tmp_len > 0)
						continue;

					if (tp->tunnel_type == NATNL_TUNNEL_TYPE_UPNP_TCP) {
						cd->udp_tmp_len = UPNP_TCP_MSG_MAX_LEN;
					}
					else if (tp->tunnel_type == NATNL_TUNNEL_TYPE_TURN) {
						cd->udp_tmp_len = TURN_MSG_MAX_LEN;
					} else
						cd->udp_tmp_len = UDP_MSG_MAX_LEN;

					memset(cd->udp_tmp_data, 0, sizeof(cd->udp_tmp_data));
					ret = msg_recv_msg(sock, &src_sock, cd->udp_tmp_data, &cd->udp_tmp_len);
					sock_get_addrstr(&src_sock, addr_str, 20);
					src_port = sock_get_port(&src_sock);
					if (ret == 0)
					{
						client = get_client_by_src_sock(cd->clients, src_sock);
						if (client)
						{
							if (cd->udp_tmp_len != 0 && client->udp2tcp_len == 0)
							{
								client->tcp2udp_len = cd->udp_tmp_len;
								memset(client->tcp2udp, 0, sizeof(client->tcp2udp));
								memcpy(client->tcp2udp, cd->udp_tmp_data, client->tcp2udp_len);
							}
							if (!client_is_working(client))
								continue;
						}
					}
					else
						cd->udp_tmp_len = 0;
				}
#endif

				if(sock->type == SOCK_STREAM)
					session = client_create(next_req_id++, in_sock, NULL, 1);
#if 0
				else if (sock->type == SOCK_DGRAM) {
					if (!client) {// DEAN. if without checking client is null, there will be memory leak.
						client = client_create(next_req_id++, sock, tp, 1);
						is_first_udp_packet = 1;
					}
				}
#endif
#ifdef UDP
				if (sock->type == SOCK_DGRAM && cd->udp_tmp_len != 0 && session->udp2tcp_len == 0)
				{
					session->tcp2udp_len = cd->udp_tmp_len;
					memset(session->tcp2udp, 0, sizeof(session->tcp2udp));
					memcpy(session->tcp2udp, cd->udp_tmp_data, session->tcp2udp_len);
				}
#endif

				if(!session) {
					sock_close(in_sock);
				} else {
					if (sock->type == SOCK_STREAM || (sock->type == SOCK_DGRAM && is_first_udp_packet)) {
#if 0
						if (sock->type == SOCK_DGRAM)
							memcpy(&client->src_sock, &src_sock, sizeof(socket_t));
#endif

						session2 = (client_t *)natnl_list_add(im_sessions, session, 1);
		                
						//session2->role = CLIENT_ROLE_CLIENT;

						client_add_fd_to_set(session2, &read_fds, NULL);

						session_set_status(session2, IM_SESSION_STATUS_READY);

						// Save client id to sock for logs.
						session2->sock->client_id = session2->id; 
						PJ_LOG(4, (THIS_FILE, "im_lport_thread() client obj created. client->id=[%d], LIST_LEN(im_sessions)=[%d]", 
							session2->id, LIST_LEN(im_sessions)));
					}
				}

				// free tcp_sock here, because sock_copy was used in client_create.
				if (sock->type == SOCK_STREAM)
					sock_free(&in_sock);

				//num_fds--;
			}
		} // end of tcp_servs for loop

		/* Go through all the clients and check if didn't get an ACK for sent
           data during the timeout period */
		if(im_sessions)
		{
			pj_status_t status;
			for(i = 0; i < LIST_LEN(im_sessions); i++) {
				//pj_thread_sleep(10000);
				session = (client_t *)natnl_list_get_at(im_sessions, i);

				if (!session)
					continue;

				// destroy session which mark as destroying
				if (session_is_status(session, IM_SESSION_STATUS_DESTROYING) && 
					session->im_user_data &&
					((struct natnl_data *)session->im_user_data)->status >= 0) {
					PJ_LOG(2, (THIS_FILE, "im_lport_thread() disconnect_and_remove_client() session->id=[%d].", 
						session->id));
					((struct natnl_data *)session->im_user_data)->user_data = NULL;
					disconnect_and_remove_client(session, im_sessions, &read_fds, 1, 1);
					i--;
					continue;
				}
#if 0
				if (session->status == CLIENT_STATUS_DESTORYING || client_ready_to_disconnect(client)) {
					PJ_LOG(3, (THIS_FILE, "im_lport_thread() client is ready to disconnect. client=[%d], i=[%d].", 
						session->id, i));
					if (session->lock) {
						PJ_LOG(5, (THIS_FILE, "im_lport_thread() enter pj_mutex_trylock(), cid=[%d]", client->id));
						status = pj_mutex_trylock(client->lock);
						PJ_LOG(5, (THIS_FILE, "im_lport_thread() leave pj_mutex_trylock(), cid=[%d], status=[%d]", client->id, status));
						if (status == PJ_SUCCESS) {
							session_set_status(session, IM_SESSION_STATUS_DESTORYING);
							//if (client->lock)
							//	pj_mutex_unlock(client->lock);
						}
					}
					continue;
				}
#endif

				// TODO timeout handling.
				if(session_is_status(session, IM_SESSION_STATUS_REQUEST_SENT) && 
					client_im_timed_out(session)) {
					PJ_LOG(2, (THIS_FILE, "im_lport_thread() client_im_timed_out() session->id=[%d].", 
						session->id));
					session_set_status(session, IM_SESSION_STATUS_DESTROYING);
					continue;
				}

				// recv data from loopback
				if (session_is_status(session, IM_SESSION_STATUS_READY))
				{
					PJ_LOG(4, (THIS_FILE, "im_lport_thread() IM_SESSION_STATUS_READY. num_fds=[%d]", num_fds));
#ifdef QoS
					// 2014-01-11 DEAN, QoS
					if (session->qos_priority > session->qos_cnt)
					{
						session->qos_cnt++;
						continue;
					}

					session->qos_cnt = 0;
#endif
					if(num_fds > 0 && client_tcp_fd_isset(session, &read_fds)) {
						PJ_LOG(4, (THIS_FILE, "im_lport_thread() IM_SESSION_STATUS_READY2."));
						if (!session->im_req_buf)
							session->im_req_buf = (char*)malloc(NATNL_IM_MAX_LEN);
						ret = sock_recv_whole_data(session->sock, NULL, session->im_req_buf, NATNL_IM_MAX_LEN);
						if (ret <= 0) {
							PJ_LOG(1, (THIS_FILE, "im_lport_thread() client_recv_lo_whole_data() failed ret=[%d]. session->id=[%d].", 
								ret, session->id));
							session_set_status(session, IM_SESSION_STATUS_DESTROYING);
							continue;
						} else {
							PJ_LOG(4, (THIS_FILE, "im_lport_thread() client_recv_lo_whole_data() ok ret=[%d], session->id=[%d].", 
								ret, session->id));
							session_set_status(session, IM_SESSION_STATUS_LO_DATA_GOT);
						}

						num_fds--;
					} else {
						PJ_LOG(1, (THIS_FILE, "im_lport_thread() client_tcp_fd_isset() not set. num_fds=[%d], client_tcp_fd_isset(session, &read_fds)=[%d]", num_fds, client_tcp_fd_isset(session, &read_fds)));
					}
				} 
				else if (session_is_status(session, IM_SESSION_STATUS_LO_DATA_GOT))
				{
					char *buff = NULL;
					char *curr_sip = natnl_get_curr_sip_srv(inst_id);
					char uri_to_be_send[128];
					char s_rport[6];
					char s_timeout[64];
					pj_str_t tmp_uri, tmp_msg;
					struct natnl_data *user_data = NULL;
					PJ_LOG(4, (THIS_FILE, "im_lport_thread() IM_SESSION_STATUS_LO_DATA_GOT."));
					if (!curr_sip) {
						PJ_LOG(1, (THIS_FILE, "im_lport_thread() natnl_get_curr_sip_srv() failed. session->id=[%d].", 
							session->id));
						session_set_status(session, IM_SESSION_STATUS_DESTROYING);
					}

					buff = strstr(session->im_dest_deviceid, "@");
					if (buff && strlen(buff) > 1) { //with sip uri
						sprintf(uri_to_be_send, "sip:%s", session->im_dest_deviceid);
					} else if (buff && strlen(buff) == 1) { //with '@'
						sprintf(uri_to_be_send, "sip:%s%s", session->im_dest_deviceid, curr_sip);
					} else {
						sprintf(uri_to_be_send, "sip:%s@%s", session->im_dest_deviceid, curr_sip);
					}
					tmp_uri = pj_str(uri_to_be_send);
					tmp_msg = pj_str(session->im_req_buf);
					memset(s_rport, 0, sizeof(s_rport));
					sprintf(s_rport, "%d",session->sock->rport);
					memset(s_timeout, 0, sizeof(s_timeout));
					sprintf(s_timeout, "%d",session->sock->im_timeout_sec);

					user_data = (struct natnl_data *)malloc(sizeof(struct natnl_data));
					user_data->status = -1;
					status = pj_sem_create(pjsip_get_app_pool(inst_id), "im_sem" ,0, 1, &user_data->waiting_sem);
					if (status != PJ_SUCCESS) {
						PJ_LOG(1, (THIS_FILE, "im_lport_thread() pj_sem_create() failed ret=[%d], session->id=[%d].", 
							status, session->id));
						session_set_status(session, IM_SESSION_STATUS_DESTROYING);
					}

					user_data->user_data = session;
					session->im_user_data = user_data;
					status = pjsua_im_send(inst_id, pjsua_acc_get_default(inst_id), &tmp_uri, NULL, &tmp_msg, NULL, s_rport, NULL, s_timeout, session->im_user_data);
					if (status != PJ_SUCCESS) {
						PJ_LOG(1, (THIS_FILE, "im_lport_thread() pjsua_im_send() failed ret=[%d], session->id=[%d].", 
							status, session->id));
						session_set_status(session, IM_SESSION_STATUS_DESTROYING);
					}
					PJ_LOG(4, (THIS_FILE, "im_lport_thread() pjsua_im_send() ok ret=[%d], client->id=[%d].", 
						ret, session->id));

					gettimeofday(&session->im_request_timeout, NULL);
					session->im_request_timeout.tv_sec += session->im_timeout_sec;
					session_set_status(session, IM_SESSION_STATUS_REQUEST_SENT);
					continue;
				}
				else if (session_is_status(session, IM_SESSION_STATUS_RESPONSE_GOT))
				{
					PJ_LOG(4, (THIS_FILE, "im_lport_thread() IM_SESSION_STATUS_RESPONSE_GOT."));
					ret = client_send_lo_im_data(session);
					switch(ret) {
						case 0:
							PJ_LOG(4, (THIS_FILE, "im_lport_thread() client_send_lo_data() ok ret=%d, session->id=[%d].", 
								ret, session->id));
							break;
						case -1:
						case -2:
							PJ_LOG(1, (THIS_FILE, "im_lport_thread() client_send_lo_data failed ret=[%d]. session->id=[%d].", 
								ret, session->id));
							break;
					}
					session_set_status(session, IM_SESSION_STATUS_DESTROYING); // Done. Ready to destroy session.
				}
			}
		}		
		if (lock)
			pj_mutex_unlock(lock);
	}

	natnl_set_im_lport_thread(inst_id, NULL);
	free(arg);
	return PJ_SUCCESS;
}
