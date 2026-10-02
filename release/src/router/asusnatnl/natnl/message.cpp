/*
 * Project: udptunnel
 * File: message.c
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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#endif /*WIN32*/

#include <common.h>
#include <message.h>
#include <client.h>
#include <socket.h>
#include <client.h>

#include <pjsua-lib/pjsua.h>
#include <pjsua-lib/pjsua_internal.h>
#include <pjmedia/natnl_stream.h>
/*pjsip logging*/
#include <pj/log.h>

// DEAN
#include <natnl_lib.h>

#define SCTP_PPID_WEBRTC_DCEP 50
#define SCTP_PPID_WEBRTC_STRING 51
#define SCTP_PPID_WEBRTC_BINARY 53

#define THIS_FILE "message.c"
#ifdef WIN32
#define s_addr  S_un.S_addr /* can be used for most tcp & ip code */
#endif

int tunnel_handle_message(struct call_data *cd, client_t *c, uint16_t id, uint32_t pkt_id, 
						  uint8_t msg_type, char *data, int data_len, uint8_t proto,
						  uint8_t qos_priority, uint8_t disable_flow_control, uint16_t speed_limit,
						  pjmedia_transport *tp, natnl_list_t *clients, fd_set *client_fds);

#if 0
int client_handle_message(struct call_data *cd, client_t *c, uint16_t id, uint32_t pkt_id, 
						  uint8_t msg_type, char *data, int data_len,
						  pjmedia_transport *tp, list_t *clients, fd_set *client_fds);

extern int server_handle_message(struct call_data *cd, client_t *c, uint16_t id, uint32_t pkt_id, 
								 uint8_t msg_type, char *data, int data_len,
								 pjmedia_transport *tp, list_t *clients, fd_set *client_fds);
#endif

/* external functions */
extern PJ_DEF(struct call_data *) pjsip_get_call_data(pjsua_inst_id inst_id, pjsua_call_id call_id) ;
extern void dumpHex(char *buff, int len, int send);
extern void dumpHex2(char *buff, int len, int send);
extern PJ_DEF(pj_stun_nat_type) natnl_get_nat_type();


/*
 * Sends a message to the UDP tunnel with the specified client ID, type, and
 * data. The data can be NULL and data_len 0 if the type of message won't have
 * a body, based on the protocol.
 * Returns 0 for success, -1 on error, or -2 to close the connection.
 */
int msg_send_msg(pjmedia_transport *tp, uint16_t client_id, uint32_t pkt_id, 
				 uint8_t type, char *data, int data_len, uint8_t proto, 
				 uint8_t qos_priority, uint8_t disable_flow_control, uint16_t speed_limit,
				 int sleep_while_sent)
{
    PJ_LOG(6, (THIS_FILE, "msg_send_msg() msg_type=[%d]", type));

    char buf[MAX_PACKET_LEN];
    int len; /* length for entire packet */
	int max_data_len;
	int hdr_len = sizeof(msg_hdr_t);
	int inst_id = tp->inst_id;
	int ret = 0;

	pjsua_call *call = &pjsua_var[inst_id].calls[tp->call_id];

	// Speed limit. Drop packet if it is over bandwidth.
	if(call->tnl_stream->tx_band->isLimited && 
		pj_bandwidthClamp(call->tnl_stream->tx_band, (pj_uint32_t)data_len) < 1)
		return PJ_EBUSY;

	max_data_len = NATNL_PKT_MAX_LEN;

	if(data_len > max_data_len) {
		PJ_LOG(2, (THIS_FILE, "msg_send_msg() data_len=[%d] exceed max_data_len=[%d]", 
			data_len, max_data_len));
		return -1;
	}

	if (type == MSG_TYPE_WEBRTC_ACK) {
		len = 1;
		*((uint8_t*)&buf[0]) = 0x2;
	} else {
		memset(buf, 0, sizeof(buf));
		switch(type)
		{
			case MSG_TYPE_HELLO:
			case MSG_TYPE_HELLOACK:
			case MSG_TYPE_DATA0:
			case MSG_TYPE_DATA1:
			case MSG_TYPE_RESUME_DATA:			
				if (disable_flow_control && (type == MSG_TYPE_DATA0 || type == MSG_TYPE_DATA1))
					memcpy(buf+NO_FLOW_CTL_SESS_MGR_HEADER_MAGIC_SIZE+hdr_len, data, data_len);
				else
					memcpy(buf+hdr_len, data, data_len);
				break;

			case MSG_TYPE_GOODBYE:
			case MSG_TYPE_KEEPALIVE:
			case MSG_TYPE_ACK0:
			case MSG_TYPE_ACK1:
			case MSG_TYPE_RESUME:
			case MSG_TYPE_HELLOACK2:
				data_len = 0;
				break;
	            
			default:
				return -4;
		}

		if (disable_flow_control && (type == MSG_TYPE_DATA0 || type == MSG_TYPE_DATA1/* || type == MSG_TYPE_GOODBYE*/)) {
			len = NO_FLOW_CTL_SESS_MGR_HEADER_MAGIC_SIZE + data_len + hdr_len;
			((pj_uint32_t *)buf)[0] = NO_FLOW_CTL_MAGIC();
			msg_init_header((msg_hdr_t *)&buf[NO_FLOW_CTL_SESS_MGR_HEADER_MAGIC_SIZE], pkt_id, 
				client_id, type, data_len, proto, qos_priority, disable_flow_control, speed_limit);
			buf[len] = 1;
		} else {
			len = data_len + hdr_len;
			msg_init_header((msg_hdr_t *)&buf[0], pkt_id, client_id, type, data_len, proto, 
				qos_priority, disable_flow_control, speed_limit);
		}
	}

    //len = sock_send(to, buf, len);
    //if(len < 0)
    //    return -1;
    //else if(len == 0)
    //    return -2;
    //else
    //    return 0;
//printf("\n\n----------------------------------\n");
//printf("[message.c] send msg via UDP tunnel to peer: tp=[%s]\n", tp->name);
    dumpHex2(buf, len, 1);
//printf("----------------------------------\n");

	//int ret = pjmedia_transport_send_rtp(tp, buf, len);
	
	// use the corresponding send function
	if (disable_flow_control && (type == MSG_TYPE_DATA0 || type == MSG_TYPE_DATA1)) {
		 pjsua_call *call = (pjsua_call *) &pjsua_var[tp->inst_id].calls[tp->call_id];
		 if (call) {
			pj_get_timestamp(&call->tnl_stream->last_data);  // DEAN save current time 
			((pj_uint8_t*)buf)[len] = 1;  // tunnel data flag on
		 }
		ret = pjmedia_transport_send_rtp(tp, buf, len);
		//if (ret != 0)
		//	PJ_LOG(4, (THIS_FILE, "msg_send_msg() msg_type=[%d], ret=[%d]", type, ret));
	} else if (tp->use_sctp) {
		ret = pjmedia_transport_send_rtp(tp, buf, len);
		/*struct sctp_sndinfo sndinfo;
		struct sockaddr_in remote_addr;

		pjsua_call *call = &pjsua_var[tp->inst_id].calls[tp->call_id];
		memset((void *) &remote_addr, 0, sizeof(struct sockaddr_in));
		remote_addr.sin_family = AF_INET;
		remote_addr.sin_port = htons(5000);
		remote_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // dean : we just assign any legal address.

		sndinfo.snd_sid = tp->sctp_stream_id;
		sndinfo.snd_flags = 0;
		if (type == MSG_TYPE_WEBRTC_ACK)
			sndinfo.snd_ppid = pj_htonl(SCTP_PPID_WEBRTC_DCEP);
		else
			sndinfo.snd_ppid = pj_htonl(SCTP_PPID_WEBRTC_BINARY);
		sndinfo.snd_context = 0;
		sndinfo.snd_assoc_id = 0;

		if (call->inv->role == PJSIP_ROLE_UAC)
			ret = usrsctp_sendv((struct socket *)tp->sctp_sock, buf, len, (struct sockaddr *) &remote_addr, 1, 
				(void *)&sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO, 0); 
		else
			ret = usrsctp_sendv((struct socket *)tp->sctp_accept_sock, buf, len, (struct sockaddr *) &remote_addr, 1, 
				(void *)&sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO, 0); */

		// TODO SCTP checking return value.
	} else {
		ret = udt_send(tp->udt_sock, buf, len, 0);
		if (ret == 0) {
			PJ_LOG(2, (THIS_FILE, "udt_send failed."));
			ret = -1;
		}
		else {
			PJ_LOG(6, (THIS_FILE, "[%d]udt_send %d bytes.", client_id, ret));
		#ifndef WIN32
			if (sleep_while_sent == 1) {
	            timespec ts;
	            ts.tv_sec = 0;
	            ts.tv_nsec = 1; // 1 nanosecond.
	            nanosleep(&ts, NULL);
	        }
		#endif
		}
	}

	if (ret < 0)
        ret = PJ_EBUSY;
	else {
		//if(!disable_flow_control)
			ret = 0;

		// for tx speed calculation
		if (call->tnl_stream->tx_band) {
			if (type == MSG_TYPE_DATA0 || type == MSG_TYPE_DATA1) {
				pj_bandwidthUsed(call->tnl_stream->tx_band, len);
			} else {
				pj_bandwidthUsed(call->tnl_stream->tx_band, 0);
			}
		}
	}

//printf("[message.c] leave msg_send_msg..ret=[%d]\n", ret);
    //DEAN

	if(ret == 0) { 
        return ret;
	} else {
		if (ret == PJ_EBUSY || 
			PJ_STATUS_TO_OS(ret) == 10055 || // Windows WSAENOBUFS(10055)
			PJ_STATUS_TO_OS(ret) == 105      // Linux ENOBUFS(105)
			) {       
				if (ret != PJ_EBUSY)
					PJ_LOG(4, (THIS_FILE, "msg_send_msg() msg_type=[%d], ret=[%d]", type, ret));
				
				//dumpHex2(buf, len, 1);
#if 0
				free(buf);
#endif
				return ret;
		} 
		PJ_LOG(4, (THIS_FILE, "msg_send_msg() msg_type=[%d], ret=[%d]", type, ret));
#if 0
		free(buf);
#endif
		return -5;
	}

}


/*
 * Sends a HELLO type message to the UDP tunnel with the specified host and
 * port in the body.
 * Returns 0 for success, -1 on error, or -2 to disconnect.
 */
int msg_send_hello(pjmedia_transport *tp, char *host, char *port, uint16_t req_id, uint8_t sock_type, 
				   uint8_t qos_priority, uint8_t disable_flow_control, uint16_t speed_limit)
{
    char data[MAX_PACKET_LEN];
    int str_len;
    int len;

	memset(data, 0, sizeof(data));
	str_len = strlen(host) + strlen(port) + 2;
	len = str_len + sizeof(req_id);

	*((uint16_t *)data) = htons(req_id);

#ifdef WIN32
    _snprintf(data + sizeof(req_id), str_len, "%s %s", host, port);
#else
    snprintf(data + sizeof(req_id), str_len, "%s %s", host, port);
#endif

#if 0
	*((uint32_t *)(data+len)) = htonl(qos_priority);
	len += sizeof(qos_priority);
#endif

    len = msg_send_msg(tp, 0, 0, MSG_TYPE_HELLO, data, len, sock_type, 
		qos_priority, disable_flow_control, speed_limit, 0);
#if 0
    free(data);
#endif

    if(len < 0)
        return -1;
    /*else if(len == 0) DEAN
        return -2;*/
    else
        return 0;
}

#if 1
/*
 * Receives a message that is ready to be read from the UDP socket. Writes the
 * body of the message into data, and sets the client ID, type, and length
 * of the message.
 * Returns 0 for success, -1 on error, or -2 to disconnect.
 */
int msg_recv_msg(socket_t *sock, socket_t *from, char *data, int *data_len)
{
	int ret;

	if (!data)
		return 0;

    ret = sock_recv(sock, from, data, *data_len);
    if(ret < 0)
        return -1;
    else if(ret == 0)
        return -2;

	*data_len = ret;

    return 0;
}
#endif

int retrieve_src_addr(socket_t *sock, socket_t *from)
{
	//char data[1447];

	return sock_recv(sock, from, NULL, 0);
}

int natnl_handle_recv_msg(pjsua_call_id call_id, pjmedia_transport *tp, 
						  char *data, int data_len)
{
	uint16_t id; 
	uint8_t type; 
	uint16_t length;
	uint32_t pkt_id;
	uint8_t proto;
	uint8_t qos_priority;
	uint8_t disable_flow_control;
	uint16_t speed_limit;
    msg_hdr_t *hdr_ptr;
    char *msg_ptr;
    int ret;

	uint8_t data_channel_hdr[16] = {0x03, 00, 00, 00, 00, 00, 00, 00, 00, 0x04, 00, 00, 0x74, 0x65, 0x73, 0x74};
	
	pjsua_call *call = &pjsua_var[tp->inst_id].calls[call_id];
	struct call_data *cd = (struct call_data *)pjsip_get_call_data(tp->inst_id, call_id);

	if (!cd)
		return -1;

	dumpHex(data, data_len, 0);
	if (!tp->remote_ua_is_sdk && 
		memcmp(data, data_channel_hdr, sizeof(data_channel_hdr)) == 0) {
		client_send_webrtc_datachannel_open_ack(tp);
		return 0;
	}

	hdr_ptr = (msg_hdr_t *)data;
	msg_ptr = data + sizeof(msg_hdr_t);
    
	id = msg_get_client_id(hdr_ptr);
	type = msg_get_type(hdr_ptr);
	length = msg_get_length(hdr_ptr);
	pkt_id = msg_get_pkt_id(hdr_ptr);
	proto = msg_get_proto(hdr_ptr);
	qos_priority = msg_get_qos_priority(hdr_ptr);
	disable_flow_control = msg_get_disable_flow_control(hdr_ptr);	
	speed_limit = msg_get_speed_limit(hdr_ptr);	

	if (proto == 0)
		proto = SOCK_TYPE_TCP;

	// Incoming tunnel keep alive packet, no need to handle that.
	if (id == 0 && type == MSG_TYPE_KEEPALIVE) 
		return 0;

	client_t *c = NULL;

	if(type == MSG_TYPE_HELLOACK) {
		uint16_t req_id = ntohs(*((uint16_t*)msg_ptr));
		client_t *client = (client_t *)natnl_list_get(cd->conn_clients, &req_id);

		if (client)
		{
			c = (client_t *)natnl_list_add(cd->clients, client, 1);
			natnl_list_delete(cd->conn_clients, client);
		}

	} else {
		c = (client_t *)natnl_list_get(cd->clients, &id);
		if (c == NULL) {
			PJ_LOG(5, (THIS_FILE, "natnl_handle_recv_msg() client is null id=[%d], type=[%d], length=[%d]", 
				id, type, length));
		}
	}

	PJ_LOG(6, (THIS_FILE, "natnl_handle_recv_msg() client=[%p]", 
		c));
	if (c != NULL)
		c->tunnel_type = tp->tunnel_type;
	ret = tunnel_handle_message(cd, c, id, pkt_id, type, msg_ptr, length, proto, qos_priority, 
				disable_flow_control, speed_limit, tp, cd->clients, &cd->client_fds);

    return 0;
}
