/*
 * Project: natnl
 * File: tunnel.c
 *
 * Copyright (C) 2009 Daniel Meekins
 * Contact: dmeekins - gmail
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
#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#else
#include "helpers/winhelpers.h"
#endif

#include <common.h>
#include <list.h>
#include <client.h>
#include <message.h>
#include <socket.h>

/*pjsip logging*/
#include <pj/log.h>

/* 2013-03-20 DEAN Added, for bandwidth control */
#include <pj/bandwidth.h>
#include <pjsua-lib/pjsua_internal.h>
#include <pjmedia/natnl_stream.h>

#define THIS_FILE "tunnel.c"

#ifdef ROUTER
#endif

extern int debug_level;

extern int ipver;
static uint16_t next_req_id;

/* internal functions */
int tunnel_handle_message(struct call_data *cd, client_t *c, uint16_t id, uint32_t pkt_id, 
						  uint8_t msg_type, char *data, int data_len, uint8_t proto, 
						  uint8_t qos_priority, uint8_t disable_flow_control, uint16_t speed_limit, 
						  pjmedia_transport *tp, natnl_list_t *clients, fd_set *client_fds);

int tunnel_destroy(pjsua_inst_id inst_id, pjsua_call_id call_id);

//static void disconnect_and_remove_client(uint16_t id, list_t *clients,
//                                         fd_set *fds, int full_disconnect, int type);

/* external functions */
extern PJ_DEF(struct call_data *) pjsip_get_call_data(pjsua_inst_id inst_id, pjsua_call_id call_id);
extern PJ_DEF(void *) natnl_get_app_data(int inst_id);

extern int natnl_resume_thread(void *arg);
extern void dumpHex3(char *buff, int len, int send);
extern int natnl_no_ctl_recv_thread(void *arg);


client_t *get_client_by_src_sock(natnl_list_t *clients, socket_t src_sock, socket_t dst_sock)
{
	client_t *client_found = NULL;
	int i;
	if (clients)
	{
		for (i = 0; i < LIST_LEN(clients); i++)
		{
			client_found = (client_t *)natnl_list_get_at(clients, i);
#if 0
			uint16_t src_port;
			char addr_str[20];
			client_found = (client_t *)list_get_at(clients, i);
			src_port = sock_get_port(&client_found->src_sock);
			sock_get_addrstr(&client_found->src_sock, addr_str, 20);
			PJ_LOG(4, (THIS_FILE, "get_client_by_src_sock() client_src_addr=%s:%d, addr_len=%d, fa=%d", 
				addr_str, src_port, client_found->src_sock.addr_len, client_found->src_sock.addr.ss_family));
#endif
			if (client_found->src_sock.type == src_sock.type && 
				sock_addr_equal(&client_found->src_sock, &src_sock) && 
				client_found->sock && client_found->sock->type == dst_sock.type && 
				sock_addr_equal(client_found->sock, &dst_sock)) {
#if 0
				src_port = sock_get_port(&client_found->src_sock);
				sock_get_addrstr(&client_found->src_sock, addr_str, 20);
				PJ_LOG(4, (THIS_FILE, "get_client_by_src_sock1() client_src_addr=%s:%d, addr_len=%d, fa=%d", 
					addr_str, src_port, client_found->src_sock.addr_len, client_found->src_sock.addr.ss_family));
				src_port = sock_get_port(&src_sock);
				sock_get_addrstr(&src_sock, addr_str, 20);
				PJ_LOG(4, (THIS_FILE, "get_client_by_src_sock() src_addr=%s:%d, addr_len=%d, fa=%d", 
					addr_str, src_port, src_sock.addr_len, src_sock.addr.ss_family));
#endif
				return client_found;
			}
		}
	}
	return NULL;
}

int update_tunnel_port(pjsua_inst_id inst_id, pjsua_call_id call_id, int action, int tnl_port_count, 
						natnl_tnl_port tnl_ports[],
						int reset_ports_cnt)
{
	int i, j;
	int add, remove;

	struct call_data *cd = (struct call_data *)pjsip_get_call_data(inst_id, call_id);

	if(!cd)
		return -1;

	if (reset_ports_cnt)
	{
		for (i = 0; i < cd->tnl_ports_cnt; i++)
			memset(&cd->tnl_ports[i], 0, sizeof(cd->tnl_ports[i]));
		cd->tnl_ports_cnt = 0;
	}

	if (action == 1 && (MAX_TUNNEL_PORT_COUNT - cd->tnl_ports_cnt) < tnl_port_count)
		return -1; // exceed the number limit of tunnel port if action is 1.

	switch(action)
	{
	case 1:
		for (i = 0; i < tnl_port_count; i++)
		{
			add = 1;
			for (j = 0; j < MAX_TUNNEL_PORT_COUNT; j++)
			{
				// check if there is duplicate tunnel port
				if ((strcmp(tnl_ports[i].lport, cd->tnl_ports[j].lport) == 0) && 
					(strcmp(tnl_ports[i].rport, cd->tnl_ports[j].rport) == 0))
				{
					add = 0;
					break;
				}
			}

			if (add == 1)
			{
				int ip_ver = 0;
				pj_str_t ip_str;
				strcpy(cd->tnl_ports[cd->tnl_ports_cnt].lport, tnl_ports[i].lport);
				strcpy(cd->tnl_ports[cd->tnl_ports_cnt].rport, tnl_ports[i].rport);
				cd->tnl_ports[cd->tnl_ports_cnt].qos_priority = tnl_ports[i].qos_priority;
				cd->tnl_ports[cd->tnl_ports_cnt].disable_flow_control = tnl_ports[i].disable_flow_control;
				cd->tnl_ports[cd->tnl_ports_cnt].speed_limit = tnl_ports[i].speed_limit;
				pj_memset(cd->tnl_ports[cd->tnl_ports_cnt].rip, 0, sizeof(cd->tnl_ports[cd->tnl_ports_cnt].rip));
				// Check if the ip string is valid ipv4 or ipv6 address.
				ip_str = pj_str(tnl_ports[i].rip);
				ip_ver = natnl_get_ip_addr_ver(&ip_str);
				if (ip_ver == 4 || ip_ver == 6)
					strncpy(cd->tnl_ports[cd->tnl_ports_cnt].rip, tnl_ports[i].rip, sizeof(cd->tnl_ports[cd->tnl_ports_cnt].rip));
				else
					strncpy(cd->tnl_ports[cd->tnl_ports_cnt].rip, "127.0.0.1", sizeof(cd->tnl_ports[cd->tnl_ports_cnt].rip));
				cd->tnl_ports_cnt++;
			}
		}
		break;
	case 2:
		for (i = 0; i < MAX_TUNNEL_PORT_COUNT; i++)
		{
			remove = 0;
			for (j = 0; j < MAX_TUNNEL_PORT_COUNT; j++)
			{
				if ((strcmp(tnl_ports[i].lport, cd->tnl_ports[j].lport) == 0) && 
					(strcmp(tnl_ports[i].rport, cd->tnl_ports[j].rport) == 0))
				{
					remove = 1;
				}

				if (remove == 1)
				{
					if (j+1 < MAX_TUNNEL_PORT_COUNT)
					{
						strcpy(cd->tnl_ports[j].lport, cd->tnl_ports[j+1].lport);
						strcpy(cd->tnl_ports[j].rport, cd->tnl_ports[j+1].rport);
					}
					else
					{
						strcpy(cd->tnl_ports[j].lport, "");
						strcpy(cd->tnl_ports[j].rport, "");
						cd->tnl_ports[cd->tnl_ports_cnt].qos_priority = 0;
						cd->tnl_ports[cd->tnl_ports_cnt].disable_flow_control = 0;
						cd->tnl_ports_cnt--;
					}
				}
			}
		}
		break;
	default:
		return -2; // unknown action.
	}
	return 0;
}

natnl_status_code tunnel_srv_socket_init(pjsua_inst_id inst_id, 
										 pjsua_call_id call_id, 
										 int parent_client_id,
										 char *lport, 
										 char *rip, 
										 char *rport,
										 int qos_priority,
										 int disable_flow_control,
										 int speed_limit)
{
	char addrstr[ADDRSTRLEN];
	natnl_status_code status;
	int error_code = 0;
	char *lhost, rhost[MAX_IP_LEN];
	socket_t *tcp_serv = NULL, *tcp_serv2 = NULL;
	int i;
	char tmp_lport[6];

	struct call_data *cd = (struct call_data *)pjsip_get_call_data(inst_id, call_id);

	if (!cd || !cd->sock_servs)
		return (natnl_status_code)PJ_EINVALIDOP;

	pj_memset(rhost, 0, sizeof(rhost));
	if (!rip || strlen(rip) == 0) {
		strcpy(rhost, "127.0.0.1");
	} else {
		strcpy(rhost, rip);
	}

	// DEAN, check if lport is already created. if so return error.
	if(cd && cd->sock_servs) {
		for (i = 0; i < LIST_LEN(cd->sock_servs); i++)
		{
			tcp_serv = (socket_t *)natnl_list_get_at(cd->sock_servs, i);

			sprintf(tmp_lport, "%d", tcp_serv->lport);
			if (tcp_serv && 
				strcmp(tmp_lport, lport) == 0)
			{
				return (natnl_status_code)PJ_EEXISTS;
			}
		}
	}

	/* Create a TCP server socket to listen for incoming connections */
	lhost = NULL;
	PJ_LOG(4, (THIS_FILE, "[%d/%d/?] tunnel_srv_socket_init() init looback server for [127.0.0.1:%s] to [%s:%s]", 
		inst_id, call_id, lport, rhost, rport));

	//DEAN loopback tcp server
	status = NATNL_SC_TNL_CREATE_SOCK_FAILED;
	error_code = sock_create(&tcp_serv, lhost, lport, rhost, rport, 
		ipver, SOCK_TYPE_TCP, 1, 1, qos_priority, disable_flow_control, speed_limit, inst_id, call_id);
	//ERROR_GOTO(THIS_FILE, tcp_serv == NULL, "Error creating TCP socket.", done);
	if (tcp_serv == NULL) {
		PJ_PERROR_GOTO(1, done, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
						"[%d/%d/?] tunnel_srv_socket_init() [%s] socket create for [127.0.0.1:%s] failed. err=[%d]", 
						inst_id, call_id, "TCP", lport, error_code));
	}

	PJ_LOG(4, (THIS_FILE, "[%d/%d/?] tunnel_srv_socket_init() Listening on TCP %s, tcp_serv->fd=[%d]", 
		inst_id, call_id, sock_get_str(tcp_serv, addrstr, sizeof(addrstr)), tcp_serv->fd));

	error_code = 0;
	status = NATNL_SC_TNL_ADD_OBJECT_FAILED;
	tcp_serv2 = (socket_t *)natnl_list_add(cd->sock_servs, tcp_serv, 1);
	sock_free(&tcp_serv); //No need to close socket fd here.
	//ERROR_GOTO(THIS_FILE, tcp_serv2 == NULL, "Error add TCP socket to list.", done);
	if (tcp_serv2 == NULL) {
		PJ_PERROR_GOTO(1, done, (THIS_FILE, status, 
			"[%d/%d/?] tunnel_srv_socket_init() [%s] Failed to add TCP scoket to list [127.0.0.1:%s].", 
			inst_id, call_id, "TCP", lport));
	}
	tcp_serv2->parent_client_id = parent_client_id;

	//DEAN loopback udp server
	status = NATNL_SC_TNL_CREATE_SOCK_FAILED;
	error_code = sock_create(&tcp_serv, lhost, lport, rhost, rport, 
		ipver, SOCK_TYPE_UDP, 1, 1, qos_priority, disable_flow_control, speed_limit, inst_id, call_id);
	//ERROR_GOTO(THIS_FILE, tcp_serv == NULL, "Error creating TCP socket.", done);
	if (tcp_serv == NULL) {
		PJ_PERROR_GOTO(1, done, (THIS_FILE, error_code + PJ_ERRNO_START_SYS, 
			"[%d/%d/?] tunnel_srv_socket_init() [%s] socket create for [127.0.0.1:%s] failed. err=[%d]", 
			inst_id, call_id, "UDP", lport, error_code));
	}

	PJ_LOG(4, (THIS_FILE, "[%d/%d/?] tunnel_srv_socket_init() Binding on UDP %s, tcp_serv->fd=[%d]", 
		inst_id, call_id, sock_get_str(tcp_serv, addrstr, sizeof(addrstr)), tcp_serv->fd));

	error_code = 0;
	status = NATNL_SC_TNL_ADD_OBJECT_FAILED;
	tcp_serv2 = (socket_t *)natnl_list_add(cd->sock_servs, tcp_serv, 1);
	sock_free(&tcp_serv); //No need to close socket fd here.
	//ERROR_GOTO(THIS_FILE, tcp_serv2 == NULL, "Error add TCP socket to list.", done);
	if (tcp_serv2 == NULL) {
		error_code = pj_get_native_netos_error();
		PJ_PERROR_GOTO(1, done, (THIS_FILE, status, 
			"[%d/%d/?] tunnel_srv_socket_init() [%s] Failed to add UDP scoket to list [127.0.0.1:%s].", 
			inst_id, call_id, "UDP", lport));
	}
	tcp_serv2->parent_client_id = parent_client_id;

	// Check if no flow control thread is created.
	if (disable_flow_control) {
		pjsua_call *call = &pjsua_var[inst_id].calls[call_id];
		if (!call->tnl_stream->no_ctl_recv_thread) {
			int ret = pj_thread_create(call->tnl_stream->pool, "natnl_no_ctl_recv_thread", &natnl_no_ctl_recv_thread,  
				(void *)call, 0, 0,
				&call->tnl_stream->no_ctl_recv_thread);
			if (ret != PJ_SUCCESS) {
				PJ_LOG(1, ("natnl.c", "tunnel_srv_socket_init() pj_thread_create natnl_no_ctl_recv_thread failed status=%d", ret));
			}
		}
	}
	
	return (natnl_status_code)0;
done:
	return status;
}

natnl_status_code tunnel_srv_socket_destroy(pjsua_inst_id inst_id, pjsua_call_id call_id, 
											char *lport, char *rport)
{
	int i;
	socket_t *tcp_serv = NULL;
	struct call_data *cd = (struct call_data *)pjsip_get_call_data(inst_id, call_id);
	char tmp_lport[6], tmp_rport[6];

	if(cd && cd->sock_servs) {
		for (i = 0; i < LIST_LEN(cd->sock_servs); i++)
		{
			tcp_serv = (socket_t *)natnl_list_get_at(cd->sock_servs, i);

			sprintf(tmp_lport, "%d", tcp_serv->lport);
			sprintf(tmp_rport, "%d", tcp_serv->rport);
			if (tcp_serv && 
				strcmp(tmp_lport, lport) == 0 &&
				strcmp(tmp_rport, rport) == 0)
			{
				sock_close(tcp_serv);
				//sock_free(tcp_serv);
				natnl_list_delete(cd->sock_servs, tcp_serv);
				PJ_LOG(4, (THIS_FILE, "tunnel_srv_socket_destroy() close sock."));
			}
		}
	}
	return (natnl_status_code)0;
}

int tunnel_init(pjsua_inst_id inst_id, pjsua_call_id call_id, int bandwidth_limit) 
{

	natnl_status_code status = (natnl_status_code)0;
	int error_code = 0;

	PJ_LOG(4, (THIS_FILE, "tunnel_init() call_id=[%d]", call_id));

	struct call_data *cd = (struct call_data *)pjsip_get_call_data(inst_id, call_id);

	socket_t *tcp_serv = NULL, *tcp_serv2 = NULL;

	if (!cd)
		goto done;

	srand(time(NULL));
	next_req_id = rand() % 0xffff;
	cd->next_client_id = 1;

	if (!cd->clients) 
	{
		/* Create an empty list for the clients */
		status = NATNL_SC_TNL_CREATE_LIST_FAILED;
		cd->clients = natnl_list_create(inst_id, call_id, sizeof(client_t), p_client_cmp, p_client_copy,
										p_client_free, 0);
		//ERROR_GOTO(THIS_FILE, cd->clients == NULL, "Error creating clients list.", done);
		if (cd->clients == NULL) {
			PJ_PERROR_GOTO(1, done, (THIS_FILE, status, 
				"[%d/%d/?] tunnel_init() Failed to create clients list.", 
				inst_id, call_id));
		}
	}

	if (!cd->conn_clients)
	{
		status = NATNL_SC_TNL_CREATE_LIST_FAILED;
		/* Create and empty list for the connecting clients */
		cd->conn_clients = natnl_list_create(inst_id, call_id, sizeof(client_t), p_client_cmp, p_client_copy,
										p_client_free, 0);
		//ERROR_GOTO(THIS_FILE, cd->conn_clients == NULL, "Error creating clients list.", done);
		if (cd->clients == NULL) {
			PJ_PERROR_GOTO(1, done, (THIS_FILE, status, 
				"[%d/%d/?] tunnel_srv_socket_init() Failed to create conn_clients list.", 
				inst_id, call_id));
		}
	}

	if (!cd->sock_servs)
	{
		status = NATNL_SC_TNL_CREATE_LIST_FAILED;
		/* Create an empty list for the sockets */
		cd->sock_servs = natnl_list_create(inst_id, call_id, sizeof(socket_t), NULL, NULL, p_socket_t_free, 0);
		//ERROR_GOTO(THIS_FILE, cd->sock_servs == NULL, "Error creating socket list.", done);
		if (cd->clients == NULL) {
			PJ_PERROR_GOTO(1, done, (THIS_FILE, status, 
				"[%d/%d/?] tunnel_init() Failed to create sock_servs list.", 
				inst_id, call_id));
		}

		PJ_LOG(4, (THIS_FILE, "tunnel_init() sizeof(socket_t)=[%d]", 
					sizeof(socket_t)));
	}

	// 2013-03-20 DEAN Added, init bandwidth control structure
	cd->band = (pj_band_t *)malloc(sizeof(pj_band_t));
	pj_memset(cd->band, 0, sizeof(pj_band_t));
	pj_bandwidthSetLimited(cd->band, PJ_FALSE);
	if (bandwidth_limit) {
		pj_bandwidthSetLimited(cd->band, PJ_TRUE);
		pj_bandwidthSetDesiredSpeed_Bps(cd->band, bandwidth_limit*1024);
	}

	{
		int i;

		PJ_LOG(4, (THIS_FILE, "tunnel_init() tunnel_srv_socket_init() cd->tnl_ports_cnt=[%d]", 
			cd->tnl_ports_cnt));
		for (i = 0; i < cd->tnl_ports_cnt; i++) {
			status = tunnel_srv_socket_init(inst_id, call_id, -1, cd->tnl_ports[i].lport, 
				cd->tnl_ports[i].rip, 
				cd->tnl_ports[i].rport, 
				cd->tnl_ports[i].qos_priority, 
				cd->tnl_ports[i].disable_flow_control, 
				cd->tnl_ports[i].speed_limit);
			if (status != PJ_SUCCESS)
				goto done;
		}
	}

	FD_ZERO(&cd->client_fds);
	cd->nfds = 0;

	status = NATNL_SC_TNL_OK;
	return status;

done:
	/*if (status != 0) {
		tunnel_destroy(inst_id, call_id);
	}*/
	return status;

}

/*
 * UDP Tunnel server main(). Handles program arguments, initializes everything,
 * and runs the main loop.
 */
int tunnel_run(pjsua_inst_id inst_id, pjsua_call_id call_id, pjmedia_transport *tp)
{
	int ret;

	client_t *client = NULL;
	client_t *client2;
	socket_t *in_sock = NULL;
    
    struct timeval curr_time;
    struct timeval timeout;

	fd_set read_fds;
	socket_t *sock;
    int num_fds;

    int i;

	//pjmedia_transport *tp = NULL;	// +Roger

	struct call_data *cd = (struct call_data *)pjsip_get_call_data(inst_id, call_id);

	if (!cd)
		return 0;

	//PJ_LOG(4, (THIS_FILE, "tunnel_run() .......1"));	

	/* Initialize all the timers */
    timerclear(&timeout);
	timeout.tv_sec = 0;
	timeout.tv_usec = 10000;  // Fine tune tunnel session creating.

	char rhost[MAX_IP_LEN];
	char rport[6];

	{
		gettimeofday(&curr_time, NULL);
		// +Roger
		//tp = (pjmedia_transport *) pjsua_get_media_transport(inst_id, call_id);
		if (tp && tp->remote_ua_is_sdk)
			check_and_send_tcp_keepalive(tp, curr_time);

		if (LIST_LEN(cd->sock_servs) == 0 && LIST_LEN(cd->clients) == 0)
			pj_thread_sleep(100);

		/* Reset the file desc. set */
		//read_fds = cd->client_fds;
		FD_ZERO(&read_fds);

		cd->nfds = 0;

		for(i = 0; i < LIST_LEN(cd->sock_servs); i++) {
			sock = (socket_t *)natnl_list_get_at(cd->sock_servs, i);

			//if(!FD_ISSET(SOCK_FD(sock), &read_fds)) {
				uint16_t port;
				cd->nfds = my_max(cd->nfds, SOCK_FD(sock));
				FD_SET(SOCK_FD(sock), &read_fds);
				port = sock_get_port(sock);
				PJ_LOG(6, (THIS_FILE, "LOG FD_SET server_sock_type=%d, parent_client_id=[%d], dst_port=%d, fd=%d, max_nfds=%d", 
					sock->type, sock->parent_client_id, port, SOCK_FD(sock), cd->nfds));
			//}
		}

		for(i = 0; i < LIST_LEN(cd->clients); i++) {
			client = (client_t *)natnl_list_get_at(cd->clients, i);

			if(client && client_is_working(client)) {
				uint16_t port;
				cd->nfds = my_max(cd->nfds, SOCK_FD(client->sock));
				FD_SET(SOCK_FD(client->sock), &read_fds);
				port = sock_get_port(client->sock);
				PJ_LOG(6, (THIS_FILE, "LOG FD_SET client_sock_type=%d, parent_client_id=[%d], dst_port=%d, fd=%d, max_nfds=%d", 
					client->sock->type, client->sock->parent_client_id, port, SOCK_FD(client->sock), cd->nfds));
			}
		}


//#if defined(PJ_CONFIG_IPHONE) && (PJ_CONFIG_IPHONE != 0)
		num_fds = select(cd->nfds+1, &read_fds, NULL, NULL, &timeout);
		// 2013-11-05 DEAN, recover accept operation.
		/* Check if pending TCP connection to accept and create a new client
		   and UDP connection if one is ready */
		for(i = 0; i < LIST_LEN(cd->sock_servs); i++) {
			socket_t src_sock = { 0 };
			int is_first_udp_packet = 0;
			uint16_t port;
			sock = (socket_t *)natnl_list_get_at(cd->sock_servs, i);
			port = sock_get_port(sock);
			//PJ_LOG(4, (THIS_FILE, "LOG0 sock_type=%d, dst_port=%d", sock->type, port));

			//tp = (pjmedia_transport *)pjsua_get_media_transport(inst_id, call_id);

			/* Check if pending TCP connection to accept and create a new client
			   and UDP connection if one is ready */
			if(FD_ISSET(SOCK_FD(sock), &read_fds)) {
				PJ_LOG(6, (THIS_FILE, "tcp_tunnel_run() cd->tcp_serv is pending."));

				// Prepare remote tuple (rhost:rport)
				pj_memset(rhost, 0, sizeof(rhost));
				if (strlen(sock->rip))
					strcpy(rhost, sock->rip);
				else
					strcpy(rhost, sock->rip);
				pj_memset(rport, 0, sizeof(rport));
				sprintf(rport, "%u", sock->rport);
				if (sock->type == SOCK_STREAM) // DEAN, for loopback tcp connection.
				{
					in_sock = sock_accept(sock);
					if(in_sock == NULL) {
						PJ_LOG(1, (THIS_FILE, "tunnel_run() sock_accept tcp_sock is null."));					
						return 0;
					}
				}
				else if (sock->type == SOCK_DGRAM)// DEAN, for loopback udp connection.
				{
					char addr_str[20];
					uint16_t src_port, dst_port;

					if (cd->udp_tmp_len > 0)
						continue;

					PJ_LOG(5, (THIS_FILE, "LOG1"));

					cd->udp_tmp_len = NATNL_PKT_MAX_LEN;

					memset(cd->udp_tmp_data, 0, sizeof(cd->udp_tmp_data));
					ret = msg_recv_msg(sock, &src_sock, cd->udp_tmp_data, &cd->udp_tmp_len);
					sock_get_addrstr(&src_sock, addr_str, 20);
					src_port = sock_get_port(&src_sock);
					dst_port = sock_get_port(sock);
					PJ_LOG(5, (THIS_FILE, "LOG2 src_port=%d, dst_port=%d", src_port, dst_port));
					if (ret == 0)
					{
						client = get_client_by_src_sock(cd->clients, src_sock, *sock);
						if (client)
						{
							src_port = sock_get_port(&client->src_sock);
							dst_port = sock_get_port(client->sock);
							PJ_LOG(5, (THIS_FILE, "LOG3 client src_port=%d, dst_port=%d", src_port, dst_port));
							if (cd->udp_tmp_len != 0 /*&& client->udp2tcp_len == 0*/)
							{
								PJ_LOG(5, (THIS_FILE, "LOG4"));
								client->tcp2udp_len = cd->udp_tmp_len;
								memset(client->tcp2udp, 0, sizeof(client->tcp2udp));
								memcpy(client->tcp2udp, cd->udp_tmp_data, client->tcp2udp_len);
								cd->udp_tmp_len = 0;
							}
							if (!client_is_working(client))
								continue;
						}
					}
					else
						cd->udp_tmp_len = 0;

					PJ_LOG(5, (THIS_FILE, "LOG5"));
				}

				if(sock->type == SOCK_STREAM)
					client = client_create(next_req_id++, in_sock, tp, 1);
				else if (sock->type == SOCK_DGRAM) {
					if (!client) {// DEAN. if without checking client is null, there will be memory leak.
						client = client_create(next_req_id++, sock, tp, 1);
						is_first_udp_packet = 1;
						PJ_LOG(5, (THIS_FILE, "LOG6"));
					}
				}

				PJ_LOG(5, (THIS_FILE, "LOG7 sock->type=%d, sock->disable_flow_control=%d, cd->udp_tmp_len=%d, client->udp2tcp_len=%d, client->tcp2udp_len=%d", 
					sock->type, sock->disable_flow_control, cd->udp_tmp_len, client->udp2tcp_len, client->udp2tcp_len));
				if (sock->type == SOCK_DGRAM && cd->udp_tmp_len != 0 && client->udp2tcp_len == 0)
				{
					client->tcp2udp_len = cd->udp_tmp_len;
					memset(client->tcp2udp, 0, sizeof(client->tcp2udp));
					memcpy(client->tcp2udp, cd->udp_tmp_data, client->tcp2udp_len);
					cd->udp_tmp_len = 0;
					PJ_LOG(5, (THIS_FILE, "LOG8"));
				}

				if(!client) {
					sock_close(in_sock);
				} else {
					if (sock->type == SOCK_STREAM || (sock->type == SOCK_DGRAM && is_first_udp_packet)) {
						if (sock->type == SOCK_DGRAM)
							memcpy(&client->src_sock, &src_sock, sizeof(socket_t));

						client2 = (client_t *)natnl_list_add(cd->conn_clients, client, 1);
						client_free(&client);
						//client = NULL;
						//client2->tp->udt_sock = udt_sock;
						client2->tp = tp;
		                
						client2->role = CLIENT_ROLE_CLIENT;
						client_send_hello(client2, rhost, rport, CLIENT_ID(client2));

						if (sock->type == SOCK_STREAM)
							client_add_fd_to_set(client2, &cd->client_fds, cd);

						// Save client id to sock for logs.
						client2->sock->client_id = client2->id; 
						PJ_LOG(4, (THIS_FILE, "tunnel_run() client obj created. call_id=[%d], client_id=[%d], disable_flow_control=[%d]", 
							call_id, client2->id, client2->disable_flow_control));
					}
				}

				// free tcp_sock here, because sock_copy was used in client_create.
				if (sock->type == SOCK_STREAM)
					sock_free(&in_sock);

				num_fds--;
			}
		} // end of tcp_servs for loop

        /* Go through all the clients and check if didn't get an ACK for sent
           data during the timeout period */
		if(cd->clients)
		{
			pj_status_t status;
			for(i = 0; i < LIST_LEN(cd->clients); i++) {
				uint16_t dst_port;
				//pj_thread_sleep(10000);
				client = (client_t *)natnl_list_get_at(cd->clients, i);

				if (!client)
					continue;

				dst_port = sock_get_port(client->sock);
				PJ_LOG(5, (THIS_FILE, "LOG10 client dst_port=%d", dst_port));

				if (client->status == CLIENT_STATUS_DESTROYING || client_ready_to_disconnect(client)) {
					PJ_LOG(3, (THIS_FILE, "tunnel_run() client is ready to disconnect. client=[%d], i=[%d].", 
						client->id, i));
					if (client->lock) {
						PJ_LOG(5, (THIS_FILE, "tunnel_run() enter pj_mutex_trylock(), cid=[%d]", client->id));
						status = pj_mutex_trylock(client->lock);
						PJ_LOG(5, (THIS_FILE, "tunnel_run() leave pj_mutex_trylock(), cid=[%d], status=[%d]", client->id, status));
						if (status == PJ_SUCCESS) 
						{
							disconnect_and_remove_client(client, cd->clients, &cd->client_fds, 1, 1);
							i--;
							//if (client->lock)
							//	pj_mutex_unlock(client->lock);
						}
					}
					continue;
				}

				if (!client_is_working(client))
					continue;

				if(!client->disable_flow_control && client_udp_timed_out(client, curr_time)) {
					if (client->lock) {
						PJ_LOG(5, (THIS_FILE, "tunnel_run() enter pj_mutex_trylock(), cid=[%d]", client->id));
						status = pj_mutex_trylock(client->lock);
						PJ_LOG(5, (THIS_FILE, "tunnel_run() leave pj_mutex_trylock(), cid=[%d], status=[%d]", client->id, status));
						if (status == PJ_SUCCESS) 
						{
							disconnect_and_remove_client(client, cd->clients, &cd->client_fds, 1, 2);
							i--;
							//if (client->lock)
							//	pj_mutex_unlock(client->lock);
						}
					}
					continue;
				}

				// recv data from loopback
				if (client->tcp2udp_len != 0 ||
					client->tcp2udp_state == CLIENT_WAIT_ACK0 ||
					client->tcp2udp_state == CLIENT_WAIT_ACK1) 
				{
					num_fds--;
					PJ_LOG(6, (THIS_FILE, "tunnel_run() buffer is not empty. client=[%d], i=[%d], num_fds=[%d], pkt_id=[%d].", 
						client->id, i, num_fds, client->tcp2udp_curr_pkt));
					//continue;
				} else {
					// 2014-01-11 DEAN, QoS
					if (client->qos_priority > client->qos_cnt)
					{
						client->qos_cnt++;
						PJ_LOG(5, (THIS_FILE, "qos_priority. client=[%d], qos=[%d], num_fds=[%d], pkt_id=[%d].", 
							client->id, client->qos_priority, num_fds, client->tcp2udp_curr_pkt));
						continue;
					}

					client->qos_cnt = 0;

					if(num_fds > 0 && client_tcp_fd_isset(client, &read_fds)) {
						ret = client_recv_lo_data(client, cd);
						if(ret == -1) {
							PJ_LOG(2, (THIS_FILE, "tunnel_run() client_recv_lo_data failed ret= -1. client=[%d], i=[%d].", 
								client->id, i));
							if (client->lock) {
								PJ_LOG(5, (THIS_FILE, "tunnel_run() enter pj_mutex_trylock(), cid=[%d]", client->id));
								status = pj_mutex_trylock(client->lock);
								PJ_LOG(5, (THIS_FILE, "tunnel_run() leave pj_mutex_trylock(), cid=[%d], status=[%d]", client->id, status));
								if (status == PJ_SUCCESS) 
								{
									disconnect_and_remove_client(client, cd->clients, &cd->client_fds, 1, 3);
									i--;
									//if (client->lock)
									//	pj_mutex_unlock(client->lock);
								}
							}
							continue;
						} else if(ret == -2) {
							PJ_LOG(2, (THIS_FILE, "tunnel_run() client_recv_lo_data failed ret= -2. client=[%d], i=[%d].", 
								client->id, i));
							if (client->lock) {
								PJ_LOG(5, (THIS_FILE, "tunnel_run() enter pj_mutex_trylock(), cid=[%d]", client->id));
								status = pj_mutex_trylock(client->lock);
								PJ_LOG(5, (THIS_FILE, "tunnel_run() leave pj_mutex_trylock(), cid=[%d], status=[%d]", client->id, status));
								if (status == PJ_SUCCESS) 
								{
									client_mark_to_disconnect(client, DISCONN_EMPTY_BUFFER);
									disconnect_and_remove_client(client, cd->clients, &cd->client_fds, 1, 4);
									i--;
									//if (client->lock)
									//	pj_mutex_unlock(client->lock);
								}
							}
							continue;
						} else {
							PJ_LOG(5, (THIS_FILE, "tunnel_run() client_recv_lo_data() ok ret=%d, client->id=%d, tcp_recv_bytes=%d.", 
								ret, client->id, client->tcp_recv_bytes));
						}

						num_fds--;
					}

				}

				// if the session is disable flow control, do rtsp request check.
				if (client->disable_flow_control) {
					if (client->role == CLIENT_ROLE_CLIENT)
						;//client_rtsp_request_check(client);
				}

				ret = client_send_tnl_data(client);
				if (ret < 0) {
					PJ_LOG(1, (THIS_FILE, "tunnel_run() client_send_tnl_data() failed. ret=[%d], i=[%d].", 
						ret, i));
					if (client->lock) {
						PJ_LOG(5, (THIS_FILE, "tunnel_run() enter pj_mutex_trylock(), cid=[%d]", client->id));
						status = pj_mutex_trylock(client->lock);
						PJ_LOG(5, (THIS_FILE, "tunnel_run() leave pj_mutex_trylock(), cid=[%d], status=[%d]", client->id, status));
						if (status == PJ_SUCCESS)
						{
							disconnect_and_remove_client(client, cd->clients, &cd->client_fds, 1, 5);
							i--;
							//if (client->lock)
							//	pj_mutex_unlock(client->lock);
						}
					}
					continue;
				} else if (client_ready_to_disconnect(client)) {
					PJ_LOG(3, (THIS_FILE, "tunnel_run() client is ready to disconnect. client=[%d], i=[%d].", 
						client->id, i));
					if (client->lock) {
						PJ_LOG(5, (THIS_FILE, "tunnel_run() enter pj_mutex_trylock(), cid=[%d]", client->id));
						status = pj_mutex_trylock(client->lock);
						PJ_LOG(5, (THIS_FILE, "tunnel_run() leave pj_mutex_trylock(), cid=[%d], status=[%d]", client->id, status));
						if (status == PJ_SUCCESS) 
						{
							disconnect_and_remove_client(client, cd->clients, &cd->client_fds, 1, 6);
							i--;
							//if (client->lock)
							//	pj_mutex_unlock(client->lock);
						}
					}
					continue;
				} else if (ret == 70011) {
					PJ_LOG(5, (THIS_FILE, "tunnel_run() client_send_tnl_data() pending. ret=[%d], i=[%d], pkt_id=[%d].", 
						ret, i, client->tcp2udp_curr_pkt));
					pj_thread_sleep(10); // To avoid high cpu usage
					continue;
				} else if (ret > 70011) {
					PJ_LOG(1, (THIS_FILE, "tunnel_run() client_send_tnl_data() failed. ret=[%d], i=[%d].", 
						ret, i));
					continue;
				}
			}
		}
    }

	return 0;
}
//--------------------------------------------------------------------------------------//

int tunnel_destroy(pjsua_inst_id inst_id, pjsua_call_id call_id)
{
	PJ_LOG(4, (THIS_FILE, "tunnel_destroy() call_id=[%d]", call_id));

	struct call_data *cd = (struct call_data *)pjsip_get_call_data(inst_id, call_id);
	int i;
	socket_t *tcp_serv;
	client_t *c;

	if(cd && cd->sock_servs) {
		for (i = 0; i < LIST_LEN(cd->sock_servs); i++) {
			tcp_serv = (socket_t *)natnl_list_get_at(cd->sock_servs, i);
			if(tcp_serv) {
				//sock_close(tcp_serv);
				PJ_LOG(4, (THIS_FILE, "tunnel_destroy() close sock."));
			}
		}
		natnl_list_free(&cd->sock_servs);
	}
    PJ_LOG(3, (THIS_FILE, "tunnel_destroy() Cleaning up...."));

    if (cd && cd->clients) {
        for (i = 0; i < LIST_LEN(cd->clients); i++) {
			c = (client_t *)natnl_list_get_at(cd->clients, i);
			if (c && c->sock) { 
                sock_close(c->sock);
                PJ_LOG(4, (THIS_FILE, "tunnel_destroy() close sock."));
            }
        }
        natnl_list_free(&cd->clients);
	}

	if(cd && cd->conn_clients) {
		natnl_list_free(&cd->conn_clients);
	}

	// 2013-03-20 DEAN Added
	if (cd && cd->band) {
		free(cd->band);
		cd->band = NULL;
	}

    PJ_LOG(3, (THIS_FILE, "tunnel_destroy() Goodbye."));

    return 0;
}

/*
 * Handles the message received from the UDP tunnel. Returns 0 for success, -1
 * for some error that it handled, and -2 if the connection should be
 * disconnected.
 */
int tunnel_handle_message(struct call_data *cd, client_t *c, uint16_t id, uint32_t pkt_id, 
						  uint8_t msg_type, char *data, int data_len, uint8_t proto,
						  uint8_t qos_priority, uint8_t disable_flow_control, uint16_t speed_limit, 
						  pjmedia_transport *tp, natnl_list_t *clients, fd_set *client_fds)
{
    client_t *c2 = NULL;
    socket_t *sock = NULL;
	int ret = 0;
	char addrstr[ADDRSTRLEN];
    
    if(!c && id != 0) {
        c = (client_t *)natnl_list_get(clients, &id);
		if(!c) {
#ifdef HTTP_DEBUG
			PJ_LOG(4, (THIS_FILE, "tunnel_handle_message() client is null. client_id=%d", id));

			if (data_len > 0 && strstr(data, "HTTP/1.1") != NULL) {
				PJ_LOG(4, (THIS_FILE, "tunnel_handle_message() client is null. client_id=%d, %s", id, data));
			}
#endif
            return -1;
        }
		c->tunnel_type = tp->tunnel_type;
    }

    if(id == 0 && msg_type != MSG_TYPE_HELLO && msg_type != MSG_TYPE_WEBRTC)
		return -2;

	// client session is destroying

	pj_status_t status;

	if (c)
	{
		if (c->status >= CLIENT_STATUS_DESTROYING) {
			return -5;  // directly return without lock
		}

		if (c->lock)
		{
			PJ_LOG(5, (THIS_FILE, "tunnel_handle_message() enter pj_mutex_lock(), cid=[%d]", c->id));
			status = pj_mutex_trylock(c->lock);
			PJ_LOG(5, (THIS_FILE, "tunnel_handle_message() leave pj_mutex_lock(), cid=[%d], status=[%d]", c->id, status));

			if (status != PJ_SUCCESS)
				return -6;  // directly return without lock
		}
	}

	dumpHex3(data, data_len, 0);

	// Check if no flow control thread is created.
	if (c && disable_flow_control) {
		pjsua_call *call = &pjsua_var[c->inst_id].calls[c->call_id];
		if (!call->tnl_stream->no_ctl_recv_thread) {
			int ret = pj_thread_create(pjsua_var[c->inst_id].pool, "natnl_no_ctl_recv_thread", &natnl_no_ctl_recv_thread,  
				(void *)call, 0, 0,
				&call->tnl_stream->no_ctl_recv_thread);
			if (ret != PJ_SUCCESS) {
				PJ_LOG(1, ("natnl.c", "tunnel_srv_socket_init() pj_thread_create natnl_no_ctl_recv_thread failed status=%d", ret));
			}
		}
	}

    switch(msg_type)
    {
		case MSG_TYPE_GOODBYE:
		{
			if (!c) {
				ret = -5;
				goto RETURN_ERROR;  // unlock first before return
			}

            PJ_LOG(4, (THIS_FILE, "tunnel_handle_message() MSG_TYPE_GOODBYE client=[%d]", 
					c->id));
			client_mark_to_disconnect(c, DISCONN_REMOTE_NOTIFY); 
			client_set_status(c, CLIENT_STATUS_DESTROYING);

			ret = -2;
			break;
		}
            
        /* Data in the hello message will be like "hostname port", possibly
           without the null terminator. This will look for the space and
           parse out the hostname or ip address and port number */
        case MSG_TYPE_HELLO:
        {
            int i;
            char port[6]; /* need this so port str can have null term. */
			uint16_t req_id;
            
            if(id != 0)
				break;

			PJ_LOG(4, (THIS_FILE, "tunnel_handle_message() MSG_TYPE_HELLO client=[%d]", 
				id));

            req_id = ntohs(*((uint16_t*)data));
            PJ_LOG(6, (THIS_FILE, "tunnel_handle_message() req_id=[%d]", req_id));

            data += sizeof(uint16_t);
            data_len -= sizeof(uint16_t);
            
            /* look for the space separating the host and port */
            for(i = 0; i < data_len; i++)
                if(data[i] == ' ')
                    break;
            if(i == data_len)
                break;

            /* null terminate the host and get the port number to the string */
            data[i++] = 0;

            PJ_LOG(5, (THIS_FILE, "tunnel_handle_message() data_len=[%d]", data_len));
            //strncpy(port, data+i, data_len-i);
            strncpy(port, data+i, sizeof(port));
            port[data_len-i] = 0;

#ifdef ROUTER
            {
            	int serve_session_manager = 0;
#if defined(RTCONFIG_AICLOUD_TUNNEL) && RTCONFIG_AICLOUD_TUNNEL==1
				char *webdav_http_port = nvram_get(NVRAM_WEBDAV_HTTP_PORT);
				char *webdav_https_port = nvram_get(NVRAM_WEBDAV_HTTPS_PORT);
				PJ_LOG(6, (THIS_FILE, "tunnel_handle_message() webdav_http_port=[%s], webdav_https_port=[%s]", webdav_http_port, webdav_https_port));
				if (webdav_http_port && strcmp(webdav_http_port, port) == 0)
					serve_session_manager = 1;
				if (webdav_https_port && strcmp(webdav_https_port, port) == 0)
					serve_session_manager = 1;
#endif

#if defined(RTCONFIG_AIHOME_TUNNEL) && RTCONFIG_AIHOME_TUNNEL==1
				char *web_http_port = nvram_get(NVRAM_WEB_HTTP_PORT) ? : "80";
				char *web_https_port = nvram_get(NVRAM_WEB_HTTPS_PORT);
				PJ_LOG(6, (THIS_FILE, "tunnel_handle_message() web_http_port=[%s], web_https_port=[%s]", web_http_port, web_https_port));
				if (web_http_port && strcmp(web_http_port, port) == 0)
					serve_session_manager = 1;
				if (web_https_port && strcmp(web_https_port, port) == 0)
					serve_session_manager = 1;

				char *sshd_enable = nvram_get(NVRAM_SSHD_ENABLE);
				char *sshd_port = nvram_get(NVRAM_SSHD_PORT);
				PJ_LOG(6, (THIS_FILE, "tunnel_handle_message() sshd_enable=[%s], sshd_port=[%s]", sshd_enable, sshd_port));
				if (sshd_enable && strcmp(sshd_enable, "1") == 0) { // WAN and LAN both
					if (sshd_port && strcmp(sshd_port, port) == 0)
						serve_session_manager = 1;
				}
#endif
            	if (serve_session_manager == 0) {
					PJ_LOG(6, (THIS_FILE, "tunnel_handle_message() disable serve_session_manager"));
            		ret = -2;
            		goto RETURN_ERROR;
            	}
			}
#endif
            
            /* Create an unconnected TCP socket for the remote host, the
               client itself, add it to the list of clients */
			ret = sock_create(&sock, data, port, NULL, 0, ipver, proto, 0, 0, qos_priority, 
								disable_flow_control, speed_limit, tp->inst_id, tp->call_id);
			//ERROR_GOTO(THIS_FILE, sock == NULL, "Error creating tcp socket", error);
			if (sock == NULL) {
				PJ_PERROR_GOTO(1, error, (THIS_FILE, ret + PJ_ERRNO_START_SYS, 
					"[%d/%d/?] tunnel_handle_message() Failed to create sock.", 
					tp->inst_id, tp->call_id));
			}

			// +Roger - Check (id = 0 for tunnel keepalive)
			if (cd->next_client_id == 0)
				cd->next_client_id++;

            c = client_create(cd->next_client_id++, sock, tp, 0);
            sock_free(&sock);
			//ERROR_GOTO(THIS_FILE, c == NULL, "Error creating client", error);
			if (c == NULL) {
				PJ_PERROR_GOTO(1, error, (THIS_FILE, ret, 
					"[%d/%d/?] tunnel_handle_message() Failed to create client.", 
					tp->inst_id, tp->call_id));
			}

            c2 = (client_t *)natnl_list_add(clients, c, 1);
			//ERROR_GOTO(THIS_FILE, c2 == NULL, "Error adding client to list", error);
			if (c2 == NULL) {
				PJ_PERROR_GOTO(1, error, (THIS_FILE, ret, 
					"[%d/%d/?] tunnel_handle_message() Failed to add client to clients list.", 
					tp->inst_id, tp->call_id));
			}

			c2->tunnel_type = tp->tunnel_type;
			c2->role = CLIENT_ROLE_SERVER;

			// Speed limit setting.
			c2->speed_limit = speed_limit;
			if (c2->speed_limit) {
				pj_bandwidthSetDesiredSpeed_Bps(c2->client_tx_band, (c2->speed_limit*1024));
				pj_bandwidthSetLimited(c2->client_tx_band, PJ_TRUE);
			} else {
				pj_bandwidthSetLimited(c2->client_tx_band, PJ_FALSE);
			}
            
            /* Send the Hello ACK message if created client successfully */
            client_send_helloack(c2, req_id);
            client_udp_reset_keepalive(c2);
			client_free(&c);
			//c = NULL;

			// Save client id to sock for logs.
			c2->sock->client_id = c2->id;
			PJ_LOG(4, (THIS_FILE, "tunnel_handle_message() client obj created. call_id=[%d], client_id=[%d], speed_limit=[%d]", 
				tp->call_id, c2->id,c2->speed_limit));
            
            break;
        }

        /* Can connect to TCP connection once received the Hello ACK */
		case MSG_TYPE_HELLOACK:
			if (!c) {
				ret = -5;
				goto RETURN_ERROR;  // unlock first before return
			}

			if (c->role == CLIENT_ROLE_CLIENT)
			{
				PJ_LOG(4, (THIS_FILE, "tunnel_handle_message() MSG_TYPE_HELLOACK change client_id [%d] => [%d]", 
					c->id, id));
				client_got_helloack(c);
				CLIENT_ID(c) = id;
				c->sock->client_id = id;
				ret = client_send_helloack(c, ntohs(*((uint16_t *)data)));

				// +Roger - Check UDTclient's udptunnel
				c->tp->tunnel_flag = MSG_TYPE_HELLOACK;	

				sock_get_str(c->sock, addrstr, sizeof(addrstr));
				PJ_LOG(6, (THIS_FILE, "tunnel_handle_message()  New connection(%d): tcp://%s", 
					CLIENT_ID(c), addrstr));

				c->rtsp_msg_check_mode = 1;
			}
			else
			{
				PJ_LOG(4, (THIS_FILE, "tunnel_handle_message() MSG_TYPE_HELLOACK(%d)", 
							msg_type));
				if(client_connect_tcp(c) != 0) {
					ret = -2;
					goto RETURN_ERROR;  // unlock first before return
				}
				client_got_helloack(c);
				client_add_fd_to_set(c, client_fds, cd);

				// DEAN. If the session is disable flow control, then send HELLO ACK2.
				if (c->disable_flow_control)
					client_send_helloack2(c);
			}
			if (c->id+1 > cd->next_client_id)
				cd->next_client_id = c->id+1;

			// DEAN. If this is client and the session is disable flow control, should wait MSG_TYPE_HELLOACK2, Don't set client is working here. 
			if ((c->role == CLIENT_ROLE_CLIENT && !c->disable_flow_control) || c->role == CLIENT_ROLE_SERVER) {
				PJ_LOG(4, (THIS_FILE, "tunnel_handle_message() Set client status to working!!"));
				client_set_status(c, CLIENT_STATUS_WORKING);
			} else {
				PJ_LOG(4, (THIS_FILE, "tunnel_handle_message() Set client status not set!!"));
			}
			break;

			/* Can connect to TCP connection once received the Hello ACK2 */
		case MSG_TYPE_HELLOACK2:
			PJ_LOG(4, (THIS_FILE, "tunnel_handle_message() MSG_TYPE_HELLOACK2 change client_id [%d]", 
				c->id));
			client_set_status(c, CLIENT_STATUS_WORKING);
			break;

        /* Resets the timeout of the client's keep alive time */
		case MSG_TYPE_KEEPALIVE:
			if (!c) {
				ret = -5;
				goto RETURN_ERROR;  // unlock first before return
			}
            PJ_LOG(6, (THIS_FILE, "tunnel_handle_message() MSG_TYPE_KEEPALIVE", 
						msg_type));
            client_udp_reset_keepalive(c);
            break;

        /* Receives the data it got from the UDP tunnel and sends it to the
           TCP connection. */
        case MSG_TYPE_DATA0:
		case MSG_TYPE_DATA1:
			if (!c) {
				ret = -5;
				goto RETURN_ERROR;  // unlock first before return
			}

			PJ_LOG(5, (THIS_FILE, "tunnel_handle_message() MSG_TYPE_DATA(%d) %d %d", 
						msg_type, data_len, pkt_id));
			if (data_len) {
				//pj_thread_sleep(10000);
#if 0 // Move to earlier.
				if (!c)
					return -4;

				pj_status_t status = pj_mutex_trylock(c->lock);
				if (status != PJ_SUCCESS)
					return -5;
#endif
				if (!client_is_working(c))
					break;

				ret = client_recv_tnl_data(c, data, data_len, pkt_id, msg_type);
				if(ret == 0) {
					if (c->disable_flow_control) {
						if (c->role == CLIENT_ROLE_CLIENT)
							;//client_rtsp_response_check(c);
						else
							client_rtsp_request_check(c);
					}

					client_udp_reset_keepalive(c); // DEAN, update udp loopback timed out time.
					ret = client_send_lo_data(c);
					if (ret == -1) {
						PJ_LOG(2, (THIS_FILE, "tunnel_handle_message() client_send_lo_data failed ret= -1. client=[%d].", 
							c->id));
						client_set_status(c, CLIENT_STATUS_DESTROYING);
						//disconnect_and_remove_client(c, cd->clients, &cd->client_fds, 1, 8);
					} else if (ret == -2) {
						PJ_LOG(2, (THIS_FILE, "tunnel_handle_message() client_send_lo_data failed ret= -2. client=[%d].", 
							c->id));
						client_mark_to_disconnect(c, DISCONN_EMPTY_BUFFER);
						client_set_status(c, CLIENT_STATUS_DESTROYING);
						//disconnect_and_remove_client(c, cd->clients, &cd->client_fds, 0, 9);
					} else {
						PJ_LOG(5, (THIS_FILE, "tunnel_handle_message() client_send_lo_data() ok ret=%d, client->id=%d, c->tcp_send_bytes=%d.", 
							ret, c->id, c->tcp_send_bytes));
					}
				} else {
					PJ_LOG(5, (THIS_FILE, "tunnel_handle_message() client_recv_tnl_data() failed ret=%d, client->id=%d.", 
						ret, c->id));
				}

#if 0 // Move to later.
				if (c->lock)
					pj_mutex_trylock(c->lock);
#endif
			}
            break;

        /* Receives the ACK from the UDP tunnel to set the internal client
           state. */
        case MSG_TYPE_ACK0:
		case MSG_TYPE_ACK1:
			if (!c) {
				ret = -5;
				goto RETURN_ERROR;  // unlock first before return
			}
            PJ_LOG(5, (THIS_FILE, "tunnel_handle_message() MSG_TYPE_ACK(%d), client=[%d]", 
						msg_type, c->id));
			ret = client_got_ack(c, msg_type);
			break;

		case MSG_TYPE_WEBRTC:
            
            /* Create an unconnected TCP socket for the remote host, the
               client itself, add it to the list of clients */
			ret = sock_create(&sock, "127.0.0.1", "8088", NULL, 0, ipver, proto, 0, 1, qos_priority, 
								disable_flow_control, speed_limit, tp->inst_id, tp->call_id);
			//ERROR_GOTO(THIS_FILE, sock == NULL, "Error creating tcp socket", error);
			if (sock == NULL) {
				PJ_PERROR_GOTO(1, error, (THIS_FILE, ret + PJ_ERRNO_START_SYS, 
					"[%d/%d/?] tunnel_handle_message() Failed to create sock.", 
					tp->inst_id, tp->call_id));
			}

			// +Roger - Check (id = 0 for tunnel keepalive)
			if (cd->next_client_id == 0)
				cd->next_client_id++;

            c = client_create(cd->next_client_id++, sock, tp, 0);
            sock_free(&sock);
			//ERROR_GOTO(THIS_FILE, c == NULL, "Error creating client", error);
			if (c == NULL) {
				PJ_PERROR_GOTO(1, error, (THIS_FILE, ret, 
					"[%d/%d/?] tunnel_handle_message() Failed to create client.", 
					tp->inst_id, tp->call_id));
			}

            c2 = (client_t *)natnl_list_add(clients, c, 1);
			//ERROR_GOTO(THIS_FILE, c2 == NULL, "Error adding client to list", error);
			if (c2 == NULL) {
				PJ_PERROR_GOTO(1, error, (THIS_FILE, ret, 
					"[%d/%d/?] tunnel_handle_message() Failed to add client to clients list.", 
					tp->inst_id, tp->call_id));
			}

			c2->tunnel_type = tp->tunnel_type;
			c2->role = CLIENT_ROLE_SERVER;
            
            /* Send the Hello ACK message if created client successfully */
            //client_send_helloack(c2, req_id);
			//client_udp_reset_keepalive(c2);
			//client_send_webrtc_datachannel_open_ack(c2);
			client_set_status(c2, CLIENT_STATUS_WORKING);
			client_free(&c);

			break;

        default:
            PJ_LOG(2, (THIS_FILE, "tunnel_handle_message() unkown msg_type=[%d]", msg_type));
            ret = -1;
			break;
	}

RETURN_ERROR:
	if (c && c->lock) {
		PJ_LOG(5, (THIS_FILE, "tunnel_handle_message() enter pj_mutex_unlock(), cid=[%d]", c->id));
		pj_mutex_unlock(c->lock);
		PJ_LOG(5, (THIS_FILE, "tunnel_handle_message() leave pj_mutex_unlock(), cid=[%d]", c->id));
	}

    return ret;

error:
    return -1;
}
