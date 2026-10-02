/*
 * Project: udptunnel
 * File: client.c
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

#ifndef WIN32
#include <sys/time.h>
#else
#include <helpers/winhelpers.h>
#endif /*WIN32*/

#include <message.h>
#include <common.h>
#include <client.h>
#include <socket.h>

#define THIS_FILE "client.c"

#define GO_BACK_N_TIMEOUT 50
//#define ENABLE_SLEEP 1
#ifdef AICAM_SMART
#define ENABLE_HTTP_RES_SPEED_LIMIT 1
#endif
//#define ENABLE_RTSP_RES_SPEED_LIMIT 1

/*pjsip logging*/
#include <pj/log.h>

/* 2013-03-20 DEAN Added, for bandwidth control */
#include <pj/bandwidth.h>

#include <natnl.h>

#include <rtsp_handler.h>


// +Roger
#define cmptimer(tvp, uvp, cmp) \
        ((tvp)->tv_sec cmp (uvp)->sec || \
         (tvp)->tv_sec == (uvp)->sec && (tvp)->tv_usec cmp (uvp)->msec)

extern PJ_DEF(struct call_data *) pjsip_get_call_data(pjsua_inst_id inst_id, pjsua_call_id call_id);
extern PJ_DEF(pj_pool_t *) pjsip_get_stream_pool(int inst_id, int call_id);

static unsigned got_count = 0;
static unsigned send_count = 0;

/*
 * Allocates and initializes a new client object.
 * id - ID number for the client to have
 * tcp_sock/udp_sock - sockets attributed to the client. this function copies
 *   the structure, so the calling function can free the sockets passed to
 *   here.
 * connected - whether the TCP socket is connected or not.
 * Returns a pointer to the new structure. Call client_free() when done with
 * it.
 */
client_t *client_create(uint16_t id, socket_t *sock, pjmedia_transport *tp,
                        int connected)
{
    client_t *c = NULL;
	pj_status_t status;

    c = (client_t *)malloc(sizeof(client_t));
    if(!c)
		goto error;

	pj_memset(c, 0, sizeof(client_t));
    
    c->id = id;
	//if (sock->type == SOCK_STREAM)
	c->sock = sock_copy(sock);
	//else if (sock->type == SOCK_DGRAM)
	//	c->udp_sock = sock_copy(sock);
    c->tp = tp;
    c->udp2tcp_state = CLIENT_WAIT_HELLO;
    c->tcp2udp_state = CLIENT_WAIT_DATA0;
    c->connected = connected;

    timerclear(&c->keepalive);
    timerclear(&c->tcp2udp_timeout);
	c->resend_count = 0;

	c->resend = 0;
	c->send_count = 0;
	c->recv_count = 0;
	c->to_disconn_tcp_srv_no_data = 0;
	c->to_disconn_remote_request = 0;
	c->tcp_recv_bytes = 0;
	c->tcp_send_bytes = 0;
    // for udp tpt improvement
	c->udp2tcp_curr_pkt = -1;
	c->tcp2udp_curr_pkt = 0;
	c->udp2tcp_buf_cnt = 0;
	c->tcp2udp_buf_cnt = 0;

	c->role = CLIENT_ROLE_NONE;

	if (sock->type == SOCK_STREAM)  // Normalization for different platform.
		c->sock_type = SOCK_TYPE_TCP;
	else
		c->sock_type = SOCK_TYPE_UDP;

	c->qos_priority = sock->qos_priority;
	c->disable_flow_control = sock->disable_flow_control;
	c->speed_limit = sock->speed_limit;
	c->qos_cnt = 0;
	c->inst_id = sock->inst_id;
	c->call_id = sock->call_id;
	c->rtsp_msg_check_mode = 0;
	c->rtsp_cseq = 0;
	c->sleep_while_data_sent = 0;
	strcpy(c->im_dest_deviceid, sock->im_dest_deviceid);
	c->im_timeout_sec = sock->im_timeout_sec;
	client_udp_reset_keepalive(c);

	c->client_tx_band = (pj_band_t *)malloc(sizeof(pj_band_t));
	pj_memset(c->client_tx_band, 0, sizeof(pj_band_t));
	pj_bandwidthSetLimited(c->client_tx_band, PJ_FALSE);

	client_set_status(c, CLIENT_STATUS_NONE);
#if 1
	if (tp) {
		pj_pool_t *pool = pjsip_get_stream_pool(tp->inst_id, tp->call_id);
		if (!pool)
			goto error;

		status = pj_mutex_create_simple(pool, NULL, &c->lock);
		if (status != PJ_SUCCESS) {
			PJ_LOG(1, (THIS_FILE, " [%d/%d/%d] client_create() pj_mutex_create_simple FAILED! status=[%d]", 
				c->inst_id, c->call_id, c->id, c->status));
			//pj_mutex_destroy(dst->dissconn_lock);
			c->lock = NULL;
		}
	}
#endif
    if((tp && !c->tp) || !c->sock)
        goto error;

	//PJ_LOG(4, (THIS_FILE, " [%d/%d/%d] client_create() client object created.", 
	//	c->inst_id, c->call_id, c->id));
    return c;
    
  error:
    if(c) {
		if(c->sock)
            sock_free(&c->sock);
        free(c);
		c = NULL;
    }

    return NULL;
}

/*
 * Performs a deep copy of the client structure.
 */
client_t *client_copy(client_t *dst, client_t *src, size_t len)
{
	pj_status_t status;

    if(!dst || !src)
        return NULL;

    memcpy(dst, src, sizeof(*src));

    dst->sock = NULL;
	dst->tp = NULL;

	if (src->sock)
	{
		dst->sock = sock_copy(src->sock);

		if(!dst->sock)
			goto error;
	}

	if (src->client_tx_band)
	{
		dst->client_tx_band = (pj_band_t *)malloc(sizeof(pj_band_t));
		pj_memset(dst->client_tx_band, 0, sizeof(pj_band_t));
		pj_bandwidthSetLimited(dst->client_tx_band, PJ_FALSE);
	}

	dst->tp = src->tp;
#if 1
	if (dst->tp) {
		pj_pool_t *pool = pjsip_get_stream_pool(dst->tp->inst_id, dst->tp->call_id);
		if (!pool)
			goto error;

		status = pj_mutex_create_simple(pool, NULL, &dst->lock);
		if (status != PJ_SUCCESS){
			PJ_LOG(1, (THIS_FILE, " [%d/%d/%d] client_copy() pj_mutex_create_simple FAILED! status=[%d]", 
				src->inst_id, src->call_id, src->id, status));
			//pj_mutex_destroy(dst->dissconn_lock);
			dst->lock = NULL;
		}
	}
#endif
	PJ_LOG(4, (THIS_FILE, " [%d/%d/%d] client_copy() client object copied.", 
		dst->inst_id, dst->call_id, dst->id));

    return dst;

  error:
    if(dst->sock)
        sock_free(&dst->sock);

    return NULL;
}

/*
 * Compares the ID of the two clients.
 */
int client_cmp(client_t *c1, client_t *c2, size_t len)
{
    if (c1 && c2)
        return c1->id - c2->id;
    else
        return 1;
}

/*
 * Releases the memory used by the client.
 */
void client_free(client_t **c)
{
    if(*c)
    {
		int inst_id = (*c)->inst_id;
		int call_id = (*c)->call_id;
		int client_id = (*c)->id;
		int i;
		call_data *cd = pjsip_get_call_data(inst_id, call_id);


		if (cd) {

			if (cd->clients) {
				for (i = 0; i < LIST_LEN(cd->clients); i++)
				{
					client_t *client = (client_t *)natnl_list_get_at(cd->clients, i);
					if (client && client->sock && client->sock->parent_client_id == (*c)->id) {
						client_set_status(client, CLIENT_STATUS_DESTROYING);
						PJ_LOG(4, (THIS_FILE, " [%d/%d/%d] client_free() Set client state as CLIENT_STATUS_DESTROYING.", 
							client->inst_id, client->call_id, client->id));
					}
				}
			}

			if (cd->sock_servs) {
				for (i = 0; i < LIST_LEN(cd->sock_servs); i++)
				{
					socket_t *tcp_serv = (socket_t *)natnl_list_get_at(cd->sock_servs, i);
					if (tcp_serv && tcp_serv->parent_client_id == (*c)->id) {
						uint16_t port = sock_get_port(tcp_serv);
						char *sock_type = (char *)(tcp_serv->type == SOCK_STREAM ? "TCP" : "UDP");
						sock_close(tcp_serv);
						//sock_free(tcp_serv);
						natnl_list_delete(cd->sock_servs, tcp_serv);
						PJ_LOG(4, (THIS_FILE, "client_free() close rtsp related sock. type=[%s] [127.0.0.1:%d]", sock_type, port));
						i--;
					}
				}
			}
		}

        PJ_LOG(4, (THIS_FILE, " [%d/%d/%d] client is freeing.", 
			inst_id, call_id, client_id));

		if ((*c)->sock) {
			sock_free(&(*c)->sock);
		}
#if 0
		if (c->tcp2udp) {
			free(c->tcp2udp);
			c->tcp2udp = NULL;
		}

		if (c->udp2tcp) {
			free(c->udp2tcp);
			c->udp2tcp = NULL;
		}
#endif

#if 1
		if ((*c)->lock) {
                   pj_mutex_destroy((*c)->lock);
                   (*c)->lock = NULL;
		}
#endif

		if ((*c)->client_tx_band) {
			free((*c)->client_tx_band);
			(*c)->client_tx_band = NULL;
		}

		// free im_req_buf
		if ((*c)->im_req_buf) {
			free((*c)->im_req_buf);
			(*c)->im_req_buf = NULL;
		}

		// free im_res_buf
		if ((*c)->im_res_buf) {
			free((*c)->im_res_buf);
			(*c)->im_res_buf = NULL;
		}
		free(*c);
		*c = NULL;

		PJ_LOG(4, (THIS_FILE, " [%d/%d/%d] client is freed.", 
			inst_id, call_id, client_id));
    }
}

/*
 * Closes the client's TCP socket (not UDP, since it is shared) and remove from
 * the fd set. If full_disconnect is set, remove the list.
 */
void disconnect_and_remove_client(client_t *c, natnl_list_t *clients,
                                  fd_set *fds, int full_disconnect, int type)
{
	PJ_LOG(4, (THIS_FILE, "disconnect_and_remove_client()"));

    //client_t *c;

    if(c == NULL)
        return;
    
    /*c = (client_t *)list_get(clients, client);
    if(!c)
        return;*/

	PJ_LOG(4, (THIS_FILE, "[%d] disconnect_and_remove_client(), recv=%dbytes, sent=%dbytes", CLIENT_ID(c), c->tcp_send_bytes, c->tcp_recv_bytes));

	client_set_status(c, CLIENT_STATUS_DESTROYING);

	if (c->sock_type == SOCK_TYPE_TCP || c->sock_type == SOCK_STREAM)
	{
		/* ok to call multiple times since fd will be -1 after first disconnect */
		client_remove_fd_from_set(c, fds);
		client_disconnect_tcp(c);
	}

    if(full_disconnect)
    {
		if (c->tp)
			client_send_goodbye(c);

        PJ_LOG(4, (THIS_FILE, "disconnect_and_remove_client() Client %d full_disconnected(%d).", 
                   CLIENT_ID(c), type));
		if (c->im_user_data) {
			free(c->im_user_data);
			c->im_user_data = NULL;
		}

        natnl_list_delete(clients, c);
        PJ_LOG(4, (THIS_FILE, "disconnect_and_remove_client() Client list delete OK " 
                   ));
    } else {
        PJ_LOG(4, (THIS_FILE, "disconnect_and_remove_client() Client %d disconnected(%d).", 
                   CLIENT_ID(c), type));
    }
}

/*
 * Releases the memory used by the mutex.
 */
void mutex_free(pj_mutex_t **mutex)
{
    if(*mutex)
	{
		PJ_LOG(4, (THIS_FILE, " mutex_free() mutex is freeing."));

        pj_mutex_destroy(*mutex);
        *mutex = NULL;

		PJ_LOG(4, (THIS_FILE, " mutex_free() mutex is freed."));
    }
}

/*
 * Connects the TCP socket of the client (wrapper for sock_connect()). Returns
 * 0 on success or -1 on error.
 */
int client_connect_tcp(client_t *c)
{
    if(!c->connected) {
        if(sock_connect(c->sock, 0) == 0) {
            c->connected = 1;
            return 0;
        }
    }

    return -1;
}

/*
 * Closes the TCP socket for the client (wrapper for sock_close()).
 */
void client_disconnect_tcp(client_t *c)
{
    if(c->connected) {
        sock_close(c->sock);
		c->connected = 0;
		PJ_LOG(4, (THIS_FILE, " [%d/%d/%d] client_disconnect_tcp() sock closed.", 
			c->inst_id, c->call_id, c->id));
    }
}

/*
 * Closes the UDP socket for the client (wrapper for sock_close()).
 */
void client_disconnect_udp(client_t *c)
{
    //sock_close(c->udp_sock);    
}

#if 0
/*
 * Receives a message from the UDP tunnel for the client. Only used in
 * udpclient program because each client has their own UDP socket. Returns 0
 * for success or -1 on error. The data is written to memory pointed to by
 * data, and the id, msg_type, and len are set from the message header.
 */
int client_recv_udp_msg(socket_t *sock, char *data, int data_len,
                        uint16_t *id, uint8_t *msg_type, uint16_t *len)
{
    int ret;
    socket_t from;

    ret = msg_recv_msg(sock, &from, data, data_len,
                       id, msg_type, len);
    if(ret < 0)
        return ret;

    if(!sock_addr_equal(client->udp_sock, &from))
        return -1;

    return 0;
}
#endif

/*
 * Sends the data in the tcp2udp buffer to the UDP tunnel. Returns 0 for
 * success, -1 on error, and -2 if needs to disconnect.
 */
int client_send_tnl_data(client_t *c)
{
    #define HTTP_PARTIAL_RES "HTTP/1.1 206 Partial Content"
    #define HTTP_OK_RES "HTTP/1.1 200 OK"
    #define RTSP_OK_RES "RTSP/1.0 200 OK"
#ifdef ENABLE_SLEEP
    #define SLEEP_CNT 10
 #endif
    uint8_t msg_type;
    int ret;
    int sleep_while_sent = 0;

	if (c->tcp2udp_len == 0) {
		return 0;
	}

    /* Set the message type it is sending. If the client is in the WAIT_ACK
       state, then it will send the same type of data again (since this would
       have been called b/c of a timeout. */
    switch(c->tcp2udp_state)
    {
        case CLIENT_WAIT_DATA0:
        case CLIENT_WAIT_ACK0:
            msg_type = MSG_TYPE_DATA0;
            break;
            
        case CLIENT_WAIT_DATA1:
        case CLIENT_WAIT_ACK1:
            msg_type = MSG_TYPE_DATA1;
            break;

		default:
			PJ_LOG(2, (THIS_FILE, 
				" [%d/%d/%d] client_send_tnl_data() unknown client state. "
				"tcp2udp_state=[%d], udp2tcp_state=[%d]", 
				c->inst_id, c->call_id, c->id, c->tcp2udp_state, c->udp2tcp_state));
            return -1;
	}

#ifdef ENABLE_SLEEP
	if (c->sleep_while_data_sent == 0 &&
		(strstr(c->tcp2udp, HTTP_PARTIAL_RES) != NULL ||
		strstr(c->tcp2udp, HTTP_OK_RES) != NULL)) {
		c->sleep_while_data_sent = 1;
	}

	if (c->sleep_while_data_sent && (c->send_count % SLEEP_CNT) == (SLEEP_CNT-1)) {
		sleep_while_sent = 1;
		PJ_LOG(5, (THIS_FILE, 
			" [%d/%d/%d] client_send_tnl_data() perform nanosleep. "
			"send_count=[%d], data_len=[%d]", 
			c->inst_id, c->call_id, c->id, c->send_count, c->tcp2udp_len));

	}
#endif

#ifdef ENABLE_HTTP_RES_SPEED_LIMIT
	// Apply speed limit.
	if (c->speed_limit == 0 &&
		(strstr(c->tcp2udp, HTTP_PARTIAL_RES) != NULL ||
		strstr(c->tcp2udp, HTTP_OK_RES) != NULL)) {
		c->speed_limit = 250;
		pj_bandwidthSetDesiredSpeed_Bps(c->client_tx_band, (c->speed_limit*1024));
		pj_bandwidthSetLimited(c->client_tx_band, PJ_TRUE);
		PJ_LOG(4, (THIS_FILE, 
			" [%d/%d/%d] client_send_tnl_data() it's http repsonse session apply speed_limit=%dKB/s. ", 
			c->inst_id, c->call_id, c->id, c->speed_limit));
	}
#endif
#ifdef ENABLE_RTSP_RES_SPEED_LIMIT
	// Apply speed limit.
	if (c->speed_limit == 0 &&
		strstr(c->tcp2udp, RTSP_OK_RES) != NULL) {
		c->speed_limit = 150;
		pj_bandwidthSetDesiredSpeed_Bps(c->client_tx_band, (c->speed_limit*1024));
		pj_bandwidthSetLimited(c->client_tx_band, PJ_TRUE);
		PJ_LOG(4, (THIS_FILE, 
			" [%d/%d/%d] client_send_tnl_data() it's rtsp repsonse session apply speed_limit=%dKB/s. ", 
			c->inst_id, c->call_id, c->id, c->speed_limit));
	}
#endif

	ret = msg_send_msg(c->tp, c->id, c->tcp2udp_curr_pkt, 
		msg_type, &c->tcp2udp[0], c->tcp2udp_len, c->sock->type, c->qos_priority, 
		c->disable_flow_control, c->speed_limit, sleep_while_sent);
    if(ret != 0) {
        PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_send_tnl_data() Failed to send data to tunnel. len=[%d], err=[%d]", 
			c->inst_id, c->call_id, c->id, c->tcp2udp_len, ret));
        return ret;
	} else {
        // DEAN added
		send_count++;
		c->udp_send_bytes += c->tcp2udp_len;
		c->send_count++;

		PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_send_tnl_data() Data was sent to tunnel. len=[%d], pkt_id=[%d], accumulate_len=[%d], accumulate_cnt=[%d]", 
			c->inst_id, c->call_id, c->id, c->tcp2udp_len, c->tcp2udp_curr_pkt, c->udp_send_bytes, send_count));

#ifdef HTTP_DEBUG
		if (strstr(c->tcp2udp, "HTTP/1.1") != NULL) {
			PJ_LOG(4, (THIS_FILE, "[%d] client_send_tnl_data() sock_type=%d[%d][%d], %s", c->id, c->sock_type, SOCK_STREAM, SOCK_DGRAM, c->tcp2udp));
		}
#endif
		
		c->tcp2udp_curr_pkt++;
		c->tcp2udp_len = 0;
    }

    /* Set the state to wait for an ACK and set the timeout to some time in
       the future */
	c->tcp2udp_state = (msg_type == MSG_TYPE_DATA0) ?
							CLIENT_WAIT_DATA1 : CLIENT_WAIT_DATA0;

    return ret;
}

/*
 * Copy data to the internal buffer for sending to tcp connection and send ACK
 * back to tunnel. Returns 0 on success, 1 if this was "resending" data, -1
 * on error, or -2 if need to disconnect.
 */
int client_recv_tnl_data(client_t *c, char *data, int data_len, 
						uint32_t pkt_id, uint8_t msg_type)
{
    int ret;
	int max_data_len = NATNL_PKT_MAX_LEN;

    if(data_len > max_data_len) {
        PJ_LOG(2, (THIS_FILE, 
                   " [%d/%d/%d] client_recv_tnl_data() The data_len of sending data is over max_data_len=[%d].", 
                   c->inst_id, c->call_id, c->id, max_data_len));
        return -1;
	}

	// free the previously allocate data memory first
	if (c->udp2tcp_len > 0) {
		c->udp2tcp_len = 0;
	}

	// DEAN, don't check ACK if use tcp
	got_count++;
	c->udp_recv_bytes += data_len;

	memcpy(c->udp2tcp, data, data_len);
	c->udp2tcp_len = data_len;
	c->udp2tcp_curr_pkt = pkt_id; // 2013-06-20 DEAN, for resume packet

	PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_recv_tnl_data() Got data from tunnel. len=[%d], pkt_id=[%d], accumulate_len=[%d], accumulate_cnt=[%d]", 
		c->inst_id, c->call_id, c->id, data_len, c->udp2tcp_curr_pkt, c->udp_recv_bytes, got_count));
    
    /* Set the state to wait for the next type of data */
    c->udp2tcp_state = c->udp2tcp_state == CLIENT_WAIT_DATA0 ?
        CLIENT_WAIT_DATA1 : CLIENT_WAIT_DATA0;

#ifdef HTTP_DEBUG
	if (strstr(c->udp2tcp, "HTTP/1.1") != NULL) {
		PJ_LOG(4, (THIS_FILE, "[%d] client_recv_tnl_data() sock_type=%d[%d][%d], %s", c->id, c->sock_type, SOCK_STREAM, SOCK_DGRAM, c->udp2tcp));
	}
#endif
    
    return 0;
}

/*
 * Send data received from UDP tunnel to TCP connection. Need to call
 * client_got_tnl_data() first. Returns -1 on general error, -2 if need to
 * disconnect, and 0 on success.
 */
int client_send_lo_data(client_t *c)
{
    int ret;

	if (c->role == CLIENT_ROLE_SERVER || c->sock_type == SOCK_STREAM)
		ret = sock_send(c->sock, c->udp2tcp, c->udp2tcp_len);
	else
		ret = sock_send(&c->src_sock, c->udp2tcp, c->udp2tcp_len);

	if(ret < 0)
		return -1;
	else if(ret == 0)
		return -2;
	else {
		c->tcp_send_bytes += ret;

		PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_send_lo_data() Data was sent to [127.0.0.1:%d]. len=[%d], pkt_id=[%d], accumulate_len=[%d]", 
			c->inst_id, c->call_id, c->id, c->sock->lport, c->udp2tcp_len, c->udp2tcp_curr_pkt, c->tcp_send_bytes));

#ifdef HTTP_DEBUG
		if (strstr(c->udp2tcp, "HTTP/1.1") != NULL) {
			PJ_LOG(4, (THIS_FILE, "[%d] client_send_lo_data() sock_type=%d[%d][%d], %d bytes sent. %s", c->id, c->sock_type, SOCK_STREAM, SOCK_DGRAM, ret, c->udp2tcp));
		}
#endif
		return 0;
	}
}

/*
 * Send data received from UDP tunnel to TCP connection. Need to call
 * client_got_tnl_data() first. Returns -1 on general error, -2 if need to
 * disconnect, and 0 on success.
 */
int client_send_lo_im_data(client_t *c)
{
    int ret;

	if (c->role == CLIENT_ROLE_SERVER || c->sock_type == SOCK_STREAM)
		ret = sock_send(c->sock, c->im_res_buf, c->im_res_len);
	else
		ret = sock_send(&c->src_sock, c->im_res_buf, c->im_res_len);

	if(ret < 0)
		return -1;
	else if(ret == 0)
		return -2;
	else {
		c->tcp_send_bytes += ret;

		PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_send_lo_data() Data was sent to [127.0.0.1:%d]. len=[%d], pkt_id=[%d], accumulate_len=[%d]", 
			c->inst_id, c->call_id, c->id, c->sock->lport, c->im_res_len, c->udp2tcp_curr_pkt, c->tcp_send_bytes));

#ifdef HTTP_DEBUG
		if (strstr(c->udp2tcp, "HTTP/1.1") != NULL) {
			PJ_LOG(4, (THIS_FILE, "[%d] client_send_lo_data() sock_type=%d[%d][%d], %d bytes sent. %s", c->id, c->sock_type, SOCK_STREAM, SOCK_DGRAM, ret, c->udp2tcp));
		}
#endif
		return 0;
	}
}

/*
 * Reads data that is ready on the TCP socket and stores it in the internal
 * buffer. The routine client_send_tnl_data() send that data to the tunnel.
 */
int client_recv_lo_data(client_t *c, struct call_data *cd)
{
	int ret;
	int max_data_len = NATNL_PKT_MAX_LEN;

	// this is for safe
	if (c->tcp2udp_len > 0) {
		c->tcp2udp_len = 0;
	}

	// Session manager speed limit.
	if(c->client_tx_band->isLimited && pj_bandwidthClamp(c->client_tx_band, (pj_uint32_t)max_data_len) < 1) {
				PJ_LOG(5, (THIS_FILE, 
			" [%d/%d/%d] client_recv_lo_data() speed_limit is active. ", 
			c->inst_id, c->call_id, c->id, c->speed_limit));
		return 0;
	}

	// 2013-03-20 DEAN Added, for bandwidth control
	// Query read data
	if(cd && cd->band->isLimited && pj_bandwidthClamp(cd->band, (pj_uint32_t)max_data_len) < 1)
		return 0;

	c->tcp2udp_len = 0; // init data_len.
	memset(c->tcp2udp, 0, sizeof(c->tcp2udp));
	ret = sock_recv(c->sock, &c->src_sock, c->tcp2udp, max_data_len);
	
	if(ret < 0)
		return -1;
	if(ret == 0)
		return -2;

	// For session manager speed limit.
	if (c->client_tx_band->isLimited)
		pj_bandwidthUsed(c->client_tx_band, ret);

	// 2013-03-20 DEAN Added, for bandwidth control
	// Set length of data read.
	if (cd && cd->band->isLimited)
		pj_bandwidthUsed(cd->band, ret);


	c->tcp2udp_len = ret;
	c->tcp_recv_bytes += c->tcp2udp_len;

	PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_recv_lo_data() Received data from [127.0.0.1:%d]. len=[%d], pkt_id=[%d], accumulate_len=[%d]", 
		c->inst_id, c->call_id, c->id, c->sock->lport, c->tcp2udp_len, c->tcp2udp_curr_pkt, c->tcp_recv_bytes));

#ifdef HTTP_DEBUG
	if (strstr(c->tcp2udp, "HTTP/1.1") != NULL) {
		PJ_LOG(4, (THIS_FILE, "[%d] client_recv_lo_data() sock_type=%d[%d][%d], %d bytes recv, %s", c->id, c->sock_type, SOCK_STREAM, SOCK_DGRAM, ret, c->tcp2udp));
	}
#endif

	return 0;
}

/*
 * Reads data that is ready on the TCP socket and stores it in the internal
 * buffer. The routine client_send_tnl_data() send that data to the tunnel.
 */
int client_recv_lo_whole_data(client_t *c, struct call_data *cd)
{
	int ret;
	int max_data_len = NATNL_PKT_MAX_LEN;
	fd_set read_fds;
	struct timeval timeout;

	c->tcp2udp_len = 0; // init data_len.
	memset(c->tcp2udp, 0, sizeof(c->tcp2udp));
	do {
		ret = sock_recv(c->sock, &c->src_sock, (c->tcp2udp+c->tcp2udp_len), (max_data_len - c->tcp2udp_len));

		if(ret < 0)
			return -1;
		if(ret == 0)
			return -2;

		c->tcp2udp_len += ret;
		c->tcp_recv_bytes += ret;

		PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_recv_lo_data() Received data from [127.0.0.1:%d]. len=[%d], pkt_id=[%d], accumulate_len=[%d]", 
			c->inst_id, c->call_id, c->id, c->sock->lport, c->tcp2udp_len, c->tcp2udp_curr_pkt, c->tcp_recv_bytes));

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		FD_ZERO(&read_fds);
		FD_SET(SOCK_FD(c->sock), &read_fds);

	} while ((max_data_len - c->tcp2udp_len) > 0 && select(SOCK_FD(c->sock)+1, &read_fds, NULL, NULL, &timeout) > 0);

	return 0;
}
/*
 * Notifies the client that it got an ACK to change the internal state to
 * wait for data and remove buffer packet at head of the queue. Returns 0 if
 * ok or -1 if something weird happened.
 */
int client_got_ack(client_t *c, uint8_t ack_type)
{
    if(ack_type == MSG_TYPE_ACK0 && c->tcp2udp_state == CLIENT_WAIT_ACK0)
	{

		c->tcp2udp_len = 0;
        c->tcp2udp_state = CLIENT_WAIT_DATA1;
        c->resend_count = 0;
		c->send_count = 0;
		PJ_LOG(4, (THIS_FILE, " [%d/%d/%d] client_got_ack() Got MSG_TYPE_ACK0 state. len=[%d]", 
			c->inst_id, c->call_id, c->id, c->tcp2udp_len));

        return 0;
    }

    if(ack_type == MSG_TYPE_ACK1 && c->tcp2udp_state == CLIENT_WAIT_ACK1)
	{
		c->tcp2udp_len = 0;
        c->tcp2udp_state = CLIENT_WAIT_DATA0;
		c->resend_count = 0;
		c->send_count = 0;
		PJ_LOG(4, (THIS_FILE, " [%d/%d/%d] client_got_ack() Got MSG_TYPE_ACK1 state. len=[%d]", 
			c->inst_id, c->call_id, c->id, c->tcp2udp_len));
        return 0;
    }

    PJ_LOG(2, (THIS_FILE, " [%d/%d/%d] client_got_ack() Wrong client state. "
                         "ack_type=[%d], client->tcp2udp_state=[%d]", 
               c->inst_id, c->call_id, c->id, ack_type, c->tcp2udp_state));

    return -1;
}

/*
 * Sends a HELLO type message to the udpserver (proxy) to tell it to make a
 * TCP connection to the specified host:port.
 */
int client_send_hello(client_t *c, char *host, char *port,
                      uint16_t req_id)
{
	int res = msg_send_hello(c->tp, host, port, req_id, c->sock_type, 
		c->qos_priority, c->disable_flow_control, c->speed_limit);
	c->tp->tunnel_flag = MSG_TYPE_HELLO;	// +Roger - Check UDTclient's udptunnel
	if (res == 0)
		PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_send_hello() Hello packet was sent to tunnel. req_id=[%d]", 
               c->inst_id, c->call_id, c->id, req_id));
	else
		PJ_LOG(2, (THIS_FILE, " [%d/%d/%d] client_send_hello() Failed to send hello packet to tunnel. req_id=[%d], err=[%d]", 
		c->inst_id, c->call_id, c->id, req_id, res));

	return res;
}

/*
 * Sends a Hello ACK to the UDP tunnel.
 */
int client_send_helloack(client_t *c, uint16_t req_id)
{
    req_id = htons(req_id);
    int res = msg_send_msg(c->tp, c->id, 0, 
		MSG_TYPE_HELLOACK, (char *)&req_id, sizeof(req_id), c->sock->type, 
		c->qos_priority, c->disable_flow_control, c->speed_limit, 0);
	if (res == 0)
		PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_send_helloack() Hello ACK packet was sent to tunnel. req_id=[%d]", 
		c->inst_id, c->call_id, c->id, req_id));
	else
		PJ_LOG(2, (THIS_FILE, " [%d/%d/%d] client_send_helloack() Failed to send hello ACK packet to tunnel. req_id=[%d], err=[%d]", 
		c->inst_id, c->call_id, c->id, req_id, res));
	return res;
}

/*
 * Sends a WebRTC data channel open ACK to the UDP tunnel.
 */
int client_send_webrtc_datachannel_open_ack(pjmedia_transport *tp)
{
    int res = msg_send_msg(tp, 0, 0, 
		MSG_TYPE_WEBRTC_ACK, NULL, 0, 0, 
		0, 0, 0, 0);
	if (res == 0)
		PJ_LOG(5, (THIS_FILE, " client_send_webrtc_datachannel_open_ack() MSG_TYPE_WEBRTC_ACK packet was sent to tunnel."));
	else
		PJ_LOG(2, (THIS_FILE, " client_send_webrtc_datachannel_open_ack() Failed to send MSG_TYPE_WEBRTC_ACK packet to tunnel. err=[%d]", 
		res));
	return res;
}

/*
 * Sends a Hello ACK2 to the UDP tunnel.
 */
int client_send_helloack2(client_t *c)
{
    int res = msg_send_msg(c->tp, c->id, 0, 
		MSG_TYPE_HELLOACK2, 0, 0, c->sock->type, c->qos_priority, c->disable_flow_control, c->speed_limit, 0);
	if (res == 0)
		PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_send_helloack() Hello ACK2 packet was sent to tunnel.", 
		c->inst_id, c->call_id, c->id));
	else
		PJ_LOG(2, (THIS_FILE, " [%d/%d/%d] client_send_helloack() Failed to send hello ACK2 packet to tunnel. err=[%d]", 
		c->inst_id, c->call_id, c->id, res));
	return res;
}

/*
 * Notify the client that it got a Hello ACK.
 */
int client_got_helloack(client_t *c)
{
    PJ_LOG(5, (THIS_FILE, "client_got_helloack()"));
    if(c->udp2tcp_state == CLIENT_WAIT_HELLO) {
        c->udp2tcp_state = CLIENT_WAIT_DATA0;
        PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_got_helloack() Set client state to CLIENT_WAIT_DATA0.",
			       c->inst_id, c->call_id, c->id));
    } else {
        PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_got_helloack() Wrong state. state=[%d].", 
                   c->inst_id, c->call_id, c->id, c->udp2tcp_state));
    }
    return 0;
}

/*
 * Sends a goodbye message to the UDP server.
 */
int client_send_goodbye(client_t *c)
{
    int res = msg_send_msg(c->tp, c->id, 0, MSG_TYPE_GOODBYE, NULL, 0, c->sock->type, 
		c->qos_priority, c->disable_flow_control, c->speed_limit, 0);
	if (res == 0)
		PJ_LOG(5, (THIS_FILE, " [%d/%d/%d] client_send_goodbye() Goobye packet was sent to tunnel.", 
		c->inst_id, c->call_id, c->id));
	else
		PJ_LOG(2, (THIS_FILE, " [%d/%d/%d] client_send_goodbye() Failed to send goobye packet to tunnel. err=[%d]", 
		c->inst_id, c->call_id, c->id, res));

	return res;
}

// +Roger
int check_and_send_tcp_keepalive(pjmedia_transport *tp, struct timeval curr_tv)
{
    if(check_timed_out(tp, curr_tv))
    {
        curr_tv.tv_sec += KEEP_ALIVE_TIME;
        memcpy(&tp->keep_alive, &curr_tv, sizeof(struct timeval));

		return msg_send_msg(tp, 0, 0, 
			MSG_TYPE_KEEPALIVE, NULL, 0, SOCK_STREAM, 0, 0, 0, 0);
    }

    return 0;
}

// +Roger
int check_timed_out(pjmedia_transport *tp, struct timeval curr_tv)
{
    if(cmptimer(&curr_tv, &tp->keep_alive, >))
        return 1;
    else
        return 0;
}

/*
 * Sets the client's keepalive timeout to be the current time plus the timeout
 * period.
 */
void client_udp_reset_keepalive(client_t *client)
{
    struct timeval curr;

	if (client->sock_type == SOCK_DGRAM)
	{
		gettimeofday(&curr, NULL);
		curr.tv_sec += (pjsua_var[client->tp->inst_id].tnl_timeout_msec*5/1000);
		memcpy(&client->keepalive, &curr, sizeof(struct timeval));
	}
}

/*
 * Returns 1 if the client timed out (didn't get any data or keep alive
 * messages in the period), or 0 if it hasn't yet.
 */
int client_udp_timed_out(client_t *client, struct timeval curr_tv)
{
	if (client->sock_type == SOCK_DGRAM)
	{
		if(timercmp(&curr_tv, &client->keepalive, >))
			return 1;
	}
	return 0;
}

/*
 * Returns 1 if the im timed out (didn't get any data or keep alive
 * messages in the period), or 0 if it hasn't yet.
 */
int client_im_timed_out(client_t *client)
{
	struct timeval curr_tv;
	gettimeofday(&curr_tv, NULL);
	if(timercmp(&curr_tv, &client->im_request_timeout, >))
		return 1;
	return 0;
}

void client_set_status(client_t *client, enum client_status status) {
	if (client)
		client->status = status;
}

int client_is_working(client_t *client) {
	return client->status == CLIENT_STATUS_WORKING;
}

int client_suspend_all(int inst_id, int call_id) 
{
	int ret = PJ_SUCCESS;
	int i;
	call_data *cd = pjsip_get_call_data(inst_id, call_id);

	if (!cd->clients)
		return ret;

	for (i = 0; i < LIST_LEN(cd->clients); i++)
	{
		client_t *c = (client_t *)natnl_list_get_at(cd->clients, i);
		client_set_status(c, CLIENT_STATUS_SUSPENDED);
		PJ_LOG(4, (THIS_FILE, " [%d/%d/%d] client_suspend_all() Set client state as CLIENT_STATUS_SUSPENDED.", 
			c->inst_id, c->call_id, c->id));
	}
	return ret;
}

int client_rtsp_teardown_session(client_t *rtsp_c) {
	int i;
	call_data *cd = pjsip_get_call_data(rtsp_c->inst_id, rtsp_c->call_id);

	if (!cd->clients)
		return 0;

	for (i = 0; i < LIST_LEN(cd->clients); i++)
	{
		client_t *c = (client_t *)natnl_list_get_at(cd->clients, i);
		if (c->sock->parent_client_id == rtsp_c->id) {
			client_set_status(c, CLIENT_STATUS_DESTROYING);
			PJ_LOG(4, (THIS_FILE, " [%d/%d/%d] client_rtsp_teardown_session() Set client state as CLIENT_STATUS_DESTROYING.", 
				c->inst_id, c->call_id, c->id));
		}
	}

	return 0;
}

int client_rtsp_request_check(client_t *c) {
	char *data;
	int data_len;
	int status = 0;

	if (c->role == CLIENT_ROLE_CLIENT) {
		data = c->tcp2udp;
		data_len = c->tcp2udp_len;
	} else {
		data = c->udp2tcp;
		data_len = c->udp2tcp_len;
	}

	if (data_len == 0)
		return status;

	//if (!c->rtsp_msg_check_mode)
	//	return PJ_ENOTSUP;

	//PJ_LOG(4, (THIS_FILE, "RTSP request sent : %.*s", data_len, data));

	// Parsing packet and change to next state.
	switch (c->rtsp_state) {
		case RTSP_UNKOWN_STATE:
			if (RTSP_IS_METHOD(data, data_len, rtsp_options_method))
				c->rtsp_state = RTSP_OPTIONS_STATE;
			break;
		case RTSP_OPTIONS_STATE:
			if (RTSP_IS_METHOD(data, data_len, rtsp_decribe_method))
				c->rtsp_state = RTSP_DESCRIBE_STATE;
			break;
		case RTSP_DESCRIBE_STATE:
		case RTSP_SETUP_STATE:
			if (RTSP_IS_METHOD(data, data_len, rtsp_setup_method)) {
				c->rtsp_state = RTSP_SETUP_STATE;
				if (c->role == CLIENT_ROLE_SERVER && RTSP_IS_METHOD(data, data_len, rtsp_setup_method)) {
					rtsp_handle_setup_request(c, data, &data_len);
				}
			}
			if (RTSP_IS_METHOD(data, data_len, rtsp_play_method))
				c->rtsp_state = RTSP_PLAY_STATE;
			break;
		case RTSP_PLAY_STATE:
			//if (RTSP_IS_METHOD(data, data_len, rtsp_teardown_method)) {
				//rtsp_handle_teardown_request(c, data, &data_len);
				//c->rtsp_state = RTSP_TEARDOWN_STATE;
			//}
			break;
	}
	return status;
}

#ifdef HANDLE_REPLY
int client_rtsp_response_check(client_t *c) {
	char *data = c->udp2tcp;
	int data_len = c->udp2tcp_len;
	int status = 0;

	if (data_len == 0)
		return status;

	//if (!c->rtsp_msg_check_mode)
	//	return PJ_ENOTSUP;
	
	switch (c->rtsp_state) {
		case RTSP_UNKOWN_STATE:
			status = PJ_EBUG; // It should not happen.
			break;
		case RTSP_DESCRIBE_STATE:
			// parsing content and replace the video and audio media address.
			status = rtsp_handle_describe_reply(c->inst_id, c->call_id, data, &data_len);
			c->udp2tcp_len = data_len;
			status = PJ_SUCCESS;
			break;
		case RTSP_SETUP_STATE:
			// parsing content and bind a random port to replace server port.
			status = rtsp_handle_setup_reply(c->inst_id, c->call_id, data, &data_len);
			c->udp2tcp_len = data_len;
			status = PJ_SUCCESS;
			break;
		case RTSP_OPTIONS_STATE:
		case RTSP_PLAY_STATE:
			status = PJ_SUCCESS;
			break;
	}
	return status;
}
#endif

void dumpHex(char *buff, int len, int send) 
{
#if defined(DUMP_HEX) && DUMP_HEX == 1
#if 0
	if (len > 9)
		len = 9;
#endif
	//return; //DEAN
	if (send)
		printf("send : ");
	else 
		printf("recv : ");
	int i;
	for(i=0;i<len;i++) {
		printf("%02X", buff[i]&0xff);
		if(i%16==15)
			printf("\n");
	}
	printf("\n");
#endif
}

void dumpHex2(char *buff, int len, int send) 
{
#if defined(DUMP_HEX) && DUMP_HEX == 1
    int line;
    int max_lines = (len / 16) + (len % 16 == 0 ? 0 : 1);
    int i, out_len = 0;
	char line_buf[256];
    
    for(line = 0; line < max_lines; line++)
    {
		memset(line_buf, 0, sizeof(line_buf));
        out_len += sprintf(line_buf+out_len, "%08x  ", line * 16);

        /* print hex */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
                out_len += sprintf(line_buf+out_len, "%02x ", (uint8_t)buff[i]);
            else
                out_len += sprintf(line_buf+out_len, "   ");
        }
        out_len += sprintf(line_buf+out_len, " ");
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
                out_len += sprintf(line_buf+out_len, "%02x ", (uint8_t)buff[i]);
            else
                out_len += sprintf(line_buf+out_len, "    ");
        }

		out_len += sprintf(line_buf+out_len, " ");
        
        /* print ascii */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
            {
                if(32 <= buff[i] && buff[i] <= 126)
                    out_len += sprintf(line_buf+out_len, "%c", buff[i]);
                else
                    out_len += sprintf(line_buf+out_len, ".");
            }
			else
				out_len += sprintf(line_buf+out_len, " ");
		}
		out_len += sprintf(line_buf+out_len, "%s ", line_buf);
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
            {
				if(32 <= buff[i] && buff[i] <= 126)
					out_len += sprintf(line_buf+out_len, "%c", buff[i]);
				else
					out_len += sprintf(line_buf+out_len, ".");
            }
			else
				out_len += sprintf(line_buf+out_len, " ");
        }

        PJ_LOG(3, (THIS_FILE, "%s", line_buf));
    }
	return;
#endif
}

void dumpHex3(char *buff, int len, int send) 
{
#if defined(DUMP_HEX) && DUMP_HEX == 1
	int line;
	int max_lines;
    int i, out_len = 0;
	char line_buf[256];
	if (len > 100)
		len = 100;

	max_lines = (len / 16) + (len % 16 == 0 ? 0 : 1);
	for(line = 0; line < max_lines; line++)
	{
		memset(line_buf, 0, sizeof(line_buf));
        out_len += sprintf(line_buf+out_len, "%08x  ", line * 16);

        /* print hex */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
                out_len += sprintf(line_buf+out_len, "%02x ", (uint8_t)buff[i]);
            else
                out_len += sprintf(line_buf+out_len, "   ");
        }
        out_len += sprintf(line_buf+out_len, " ");
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
                out_len += sprintf(line_buf+out_len, "%02x ", (uint8_t)buff[i]);
            else
                out_len += sprintf(line_buf+out_len, "    ");
        }

		out_len += sprintf(line_buf+out_len, " ");

        /* print ascii */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
            {
                if(32 <= buff[i] && buff[i] <= 126)
                    out_len += sprintf(line_buf+out_len, "%c", buff[i]);
                else
                    out_len += sprintf(line_buf+out_len, ".");
            }
			else
				out_len += sprintf(line_buf+out_len, " ");
		}
		out_len += sprintf(line_buf+out_len, "%s ", line_buf);
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
            {
				if(32 <= buff[i] && buff[i] <= 126)
					out_len += sprintf(line_buf+out_len, "%c", buff[i]);
				else
					out_len += sprintf(line_buf+out_len, ".");
            }
			else
				out_len += sprintf(line_buf+out_len, " ");
        }

        PJ_LOG(3, (THIS_FILE, "%s", line_buf));
	}
	return;
#endif
}
