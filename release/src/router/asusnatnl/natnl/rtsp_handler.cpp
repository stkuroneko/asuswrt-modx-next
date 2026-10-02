
#include <stdlib.h>
#include <string.h>
#include <rtsp_handler.h>
#include <list.h>
#include <client.h>

extern int update_tunnel_port(pjsua_inst_id inst_id, pjsua_call_id call_id, 
							  int action, int tnl_ports_count, 
							  natnl_tnl_port tnl_ports[],
							  int reset_ports_cnt);
extern natnl_status_code tunnel_srv_socket_init(pjsua_inst_id inst_id, 
												pjsua_call_id call_id, 
												int parent_client_id,
												char *lport,
												char *rip, 
												char *rport,
												int qos_priority,
												int disable_flow_control,
												int speed_limit);
extern PJ_DEF(struct call_data *) pjsip_get_call_data(pjsua_inst_id inst_id, pjsua_call_id call_id);

#define THIS_FILE "rtsp_handler.c"

/*
 * Releases the memory used by the client.
 */
void rtsp_free(rtsp_line **line)
{
    if(*line)
    {

        PJ_LOG(4, (THIS_FILE, " RTSP line free %.*s.", 
			(*line)->len, (*line)->line));

		if ((*line)->line) {
			free(&(*line)->line);
			(*line)->line = NULL;
		}

        free(*line);
		*line = NULL;
    }
}

#ifdef HANDLE_REPLY
/************************************************************************/
/* Parsing c= line and replace the address.                             */
/************************************************************************/
int rtsp_handle_describe_reply(int inst_id, int call_id, void *pkt, int *pkt_len) {
	natnl_list_t * rtsp_lines = natnl_list_create(inst_id, call_id, sizeof(rtsp_line), NULL, NULL,
		p_rtsp_free, 0);
	char *desc_line;
	char *data;
	int i, count = 0, content_length_idx = -1, sdp_length = 0, out_len = 0;
	char rtsp_message[1300];

	if (*pkt_len <= 0)
		return PJ_EINVAL;

	data = (char *)malloc(*pkt_len+1);
	memcpy(data, pkt, *pkt_len+1);

	PJ_LOG(4, (THIS_FILE, " Original RTSP message %s", 
		data));

	desc_line = strtok(data, "\r\n");

	// Parse all lines and replace ip address in c= line.
	while(desc_line) {
		rtsp_line *line = (rtsp_line *)malloc(sizeof(rtsp_line));
		char buf[128];

		memset(buf, 0, sizeof(buf));
		if (strncmp(desc_line, "c=IN IP4 ", 9) == 0) { // replace ip string to 127.0.0.1.
			sprintf(buf, "c=IN IP4 %s", IP_REPLACEMENT);
			line->len = strlen(buf);
			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';
		} else if (strncmp(desc_line, "o=- ", 4) == 0) { // replace ip string to 127.0.0.1.
			char param[5][64];
			sscanf(desc_line, "o=- %s %s %s %s %s", param[0], param[1], param[2], param[3], param[4]);
			sprintf(buf, "o=- %s %s %s %s %s", param[0], param[1], param[2], param[3], IP_REPLACEMENT);
			line->len = strlen(buf);
			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';
		} else if (strncmp(desc_line, "Content-Base: ", 14) == 0) { // replace ip string to 127.0.0.1.
			//char param[5][64];
			//sscanf(desc_line, "o=- %s %s %s %s %s", param[0], param[1], param[2], param[3], param[4]);
			sprintf(buf, "Content-Base: rtsp://%s/ChannelID=1&ChannelName=Channel1/", IP_REPLACEMENT);
			line->len = strlen(buf);
			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';
		} else {
			line->len = strlen(desc_line);
			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, desc_line, line->len);
			line->line[line->len] = '\0';
		}
		PJ_LOG(4, (THIS_FILE, " RTSP line add %.*s", 
			line->len, line->line));
		natnl_list_add2(rtsp_lines, line, 0, 0); 

		if (strncmp(desc_line, "Content-Length: ", 16) == 0) {
			content_length_idx = count;
			sdp_length = 0;
		} else if (content_length_idx > 0)
			sdp_length += (line->len+2);

		count++;
		desc_line = strtok(NULL, "\r\n");
	}

	// Handle Content-Length line
	if (content_length_idx >= 0) {
		rtsp_line *line = (rtsp_line *)natnl_list_get_at(rtsp_lines, content_length_idx);
		if (strncmp(line->line, "Content-Length: ", 16) == 0) {
			char buf[128];
			sprintf(buf, "Content-Length: %d", sdp_length); // sdp length
			free(line->line);

			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';
		}
	}

	memset(rtsp_message, 0, sizeof(rtsp_message));

	// build the new RTSP message
	for (i = 0; i < count; i++) {
		rtsp_line *line = (rtsp_line *)natnl_list_get_at(rtsp_lines, i);

		out_len += sprintf(rtsp_message+out_len, "%s\r\n", line->line);

		if (content_length_idx >= 0 && i == content_length_idx)
			out_len += sprintf(rtsp_message+out_len, "%s", "\r\n");
	}
	if (!sdp_length)
		out_len += sprintf(rtsp_message+out_len, "%s", "\r\n");

	free(data);

	memcpy(pkt, rtsp_message, strlen(rtsp_message)+1);
	*pkt_len = strlen(rtsp_message);

	PJ_LOG(4, (THIS_FILE, " New RTSP message %s", 
		rtsp_message));

	return PJ_SUCCESS;
}

/************************************************************************/
/* Parsing c= line and replace the address.                             */
/************************************************************************/
int rtsp_handle_setup_reply(int inst_id, int call_id, void *pkt, int *pkt_len) {
	natnl_list_t * rtsp_lines = natnl_list_create(inst_id, call_id, sizeof(rtsp_line), NULL, NULL,
		p_rtsp_free, 0);
	char *desc_line;
	char *data;
	int i, count = 0, content_length_idx = -1, sdp_length = 0, out_len = 0;
	char rtsp_message[1300] = {0};

	if (*pkt_len <= 0)
		return PJ_EINVAL;

	data = (char *)malloc((*pkt_len)+1);
	memcpy(data, pkt, *pkt_len);
	data[*pkt_len] = '\0';

	PJ_LOG(4, (THIS_FILE, " Original RTSP message %s", 
		data));

	desc_line = strtok(data, "\r\n");

	// Parse all lines and replace ip address in c= line.
	while(desc_line) {
		rtsp_line *line = (rtsp_line *)malloc(sizeof(rtsp_line));
		char buf[128];

		memset(buf, 0, sizeof(buf));
		if (strncmp(desc_line, "c=IN IP4 ", 9) == 0) { // replace ip string to 127.0.0.1.
			sprintf(buf, "c=IN IP4 %s", IP_REPLACEMENT);
			line->len = strlen(buf);
			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';
		} else if (strncmp(desc_line, "o=- ", 4) == 0) { // replace ip string to 127.0.0.1.
			char param[5][64];
			sscanf(desc_line, "o=- %s %s %s %s %s", param[0], param[1], param[2], param[3], param[4]);
			sprintf(buf, "o=- %s %s %s %s %s", param[0], param[1], param[2], param[3], IP_REPLACEMENT);
			line->len = strlen(buf);
			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';
		} else if (strncmp(desc_line, "Content-Base: ", 14) == 0) { // replace ip string to 127.0.0.1.
			
			//char param[5][64];
			//sscanf(desc_line, "o=- %s %s %s %s %s", param[0], param[1], param[2], param[3], param[4]);
			sprintf(buf, "Content-Base: rtsp://%s/ChannelID=1&ChannelName=Channel1/", IP_REPLACEMENT);
			//sprintf(buf, "Content-Base: rtsp://%s/test.mkv", IP_REPLACEMENT);
			line->len = strlen(buf);
			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';
		} else if (strncmp(desc_line, "Transport: ", 11) == 0) { // replace ip string to 127.0.0.1.
			char param[6][64];
			sscanf(desc_line, "Transport: %[^';'];%[^';'];%[^';'];%[^';'];%[^';'];%[^';']", param[0], param[1], param[2], param[3], param[4], param[5]);
			sprintf(buf, "Transport: %s;%s;%s;source=%s;%s;%s\0", param[0], param[1], param[2], IP_REPLACEMENT, param[4], param[5]);
			line->len = strlen(buf);
			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';
		} else {
			line->len = strlen(desc_line);
			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, desc_line, line->len);
			line->line[line->len] = '\0';
		}
		PJ_LOG(4, (THIS_FILE, " RTSP line add %.*s", 
			line->len, line->line));
		natnl_list_add2(rtsp_lines, line, 0, 0); 

		if (strncmp(desc_line, "Content-Length: ", 16) == 0) {
			content_length_idx = count;
			sdp_length = 0;
		} else if (content_length_idx > 0)
			sdp_length += (line->len+2);

		count++;
		desc_line = strtok(NULL, "\r\n");
	}

	// Handle Content-Length line
	if (content_length_idx >= 0) {
		rtsp_line *line = (rtsp_line *)natnl_list_get_at(rtsp_lines, content_length_idx);
		if (strncmp(line->line, "Content-Length: ", 16) == 0) {
			char buf[128];
			sprintf(buf, "Content-Length: %d", sdp_length); // sdp length
			free(line->line);

			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';
		}
	}

	memset(rtsp_message, 0, sizeof(rtsp_message));

	// build the new RTSP message
	for (i = 0; i < count; i++) {
		rtsp_line *line = (rtsp_line *)natnl_list_get_at(rtsp_lines, i);

		out_len += sprintf(rtsp_message+out_len, "%s\r\n", line->line);

		if (content_length_idx >= 0 && i == content_length_idx)
			out_len += sprintf(rtsp_message+out_len, "%s", "\r\n");
	}
	out_len += sprintf(rtsp_message+out_len, "%s", "\r\n");
	free(data);

	memcpy(pkt, rtsp_message, strlen(rtsp_message)+1);
	*pkt_len = strlen(rtsp_message);

	PJ_LOG(4, (THIS_FILE, " New RTSP message %s", 
		rtsp_message));

	return PJ_SUCCESS;
}
#endif

int add_rtsp_tnl_ports(int inst_id, int call_id, int parent_client_id, char *port1, char *port2) {
	int ret;
	natnl_tnl_port tnl_ports[2];

	strncpy(tnl_ports[0].lport, port1, sizeof(tnl_ports[0].lport));
	strncpy(tnl_ports[0].rport, port1, sizeof(tnl_ports[0].rport));
	strncpy(tnl_ports[0].rip, "127.0.0.1", sizeof(tnl_ports[0].rip));
	strncpy(tnl_ports[1].lport, port2, sizeof(tnl_ports[1].lport));
	strncpy(tnl_ports[1].rport, port2, sizeof(tnl_ports[1].rport));
	strncpy(tnl_ports[1].rip, "127.0.0.1", sizeof(tnl_ports[1].rip));
	/*ret = update_tunnel_port(inst_id, call_id, 1, 2, tnl_ports, 0);
	if (ret != 0)
		return ret;*/

	ret = tunnel_srv_socket_init(inst_id, call_id, parent_client_id, tnl_ports[0].lport, tnl_ports[0].rip, tnl_ports[0].rport, 0, 1, 200);
	if (ret != 0)
		return ret;

	ret = tunnel_srv_socket_init(inst_id, call_id, parent_client_id, tnl_ports[1].lport, tnl_ports[1].rip, tnl_ports[1].rport, 0, 1, 200);
	if (ret != 0)
		return ret;

	// tunnel port pair information.
	{
		int i, j = 0;
		struct call_data *cd = (struct call_data *)pjsip_get_call_data(inst_id, call_id);
		int tnl_port_cnt = cd->sock_servs ? cd->sock_servs->num_objs : 0;
		socket_t *tcp_serv = NULL;

		PJ_LOG(4, (THIS_FILE, "add_rtsp_tnl_ports() tnl_port_cnt=[%d].", tnl_port_cnt));
		for (i=0; i < tnl_port_cnt; i+=2) {
			tcp_serv = (socket_t *)natnl_list_get_at(cd->sock_servs, i);
			if(tcp_serv) {
				PJ_LOG(4, (THIS_FILE, "add_rtsp_tnl_ports() tnl_ports[%d]={%d, %d, %d, %d, %d}.", 
					j, 
					tcp_serv->lport,
					tcp_serv->rport,
					tcp_serv->qos_priority,
					tcp_serv->disable_flow_control,
					tcp_serv->speed_limit));
			}
			j++;
		}
	}

	return ret;
}

/************************************************************************/
/* Parsing c= line and replace the address.                             */
/************************************************************************/
int rtsp_handle_setup_request(client_t *c, void *pkt, int *pkt_len) {
	natnl_list_t * rtsp_lines = natnl_list_create(c->inst_id, c->call_id, sizeof(rtsp_line), NULL, NULL,
		p_rtsp_free, 0);
	char *desc_line;
	char *data;
	int i, count = 0, content_length_idx = -1, sdp_length = 0;
	char rtsp_message[1300] = {0};

	if (*pkt_len <= 0)
		return PJ_EINVAL;

	data = (char *)malloc((*pkt_len)+1);
	memcpy(data, pkt, *pkt_len);
	data[*pkt_len] = '\0';

	PJ_LOG(4, (THIS_FILE, " Original RTSP message %s", 
		data));

	desc_line = strtok(data, "\r\n");

	// Parse all lines and replace ip address in c= line.
	while(desc_line) {
		rtsp_line *line = (rtsp_line *)malloc(sizeof(rtsp_line));
		char buf[128];

		memset(buf, 0, sizeof(buf));
		if (strncmp(desc_line, "Transport: ", 11) == 0) { // replace ip string to 127.0.0.1.
			char param[2][64];
			memset(param, 0, sizeof(param));
			if (strncmp(desc_line, "Transport: RTP/AVP/UDP", 22) == 0)
				sscanf(desc_line, "Transport: RTP/AVP/UDP;unicast;client_port=%[^-]-%[^-]", param[0], param[1]);
			else
				sscanf(desc_line, "Transport: RTP/AVP;unicast;client_port=%[^-]-%[^-]", param[0], param[1]);
			/*sprintf(buf, "Transport: RTP/AVP;unicast;client_port=%s-%s", param[0], param[1]);
			PJ_LOG(4, (THIS_FILE, "%s-%s", param[0], param[1]));
			line->len = strlen(buf);
			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';*/
			
			add_rtsp_tnl_ports(c->inst_id, c->call_id, c->id, param[0], param[1]);
		} 

		line->len = strlen(desc_line);
		line->line = (char *)malloc(line->len+1);
		strncpy(line->line, desc_line, line->len);
		line->line[line->len] = '\0';
		PJ_LOG(4, (THIS_FILE, " RTSP line add %.*s", 
			line->len, line->line));
		natnl_list_add2(rtsp_lines, line, 0, 0); 

		if (strncmp(desc_line, "Content-Length: ", 16) == 0) {
			content_length_idx = count;
			sdp_length = 0;
		} else if (content_length_idx > 0)
			sdp_length += (line->len+2);

		count++;
		desc_line = strtok(NULL, "\r\n");
	}

	// Handle Content-Length line
	if (content_length_idx >= 0) {
		rtsp_line *line = (rtsp_line *)natnl_list_get_at(rtsp_lines, content_length_idx);
		if (strncmp(line->line, "Content-Length: ", 16) == 0) {
			char buf[128];
			sprintf(buf, "Content-Length: %d", sdp_length); // sdp length
			free(line->line);

			line->line = (char *)malloc(line->len+1);
			strncpy(line->line, buf, line->len);
			line->line[line->len] = '\0';
		}
	}

	memset(rtsp_message, 0, sizeof(rtsp_message));

	// build the new RTSP message
	for (i = 0; i < count; i++) {
		rtsp_line *line = (rtsp_line *)natnl_list_get_at(rtsp_lines, i);

		if (i == 0)
			sprintf(rtsp_message, "%s\r\n", line->line);
		else
			sprintf(rtsp_message, "%s%s\r\n", rtsp_message, line->line);

		if (content_length_idx >= 0 && i == content_length_idx)
			sprintf(rtsp_message, "%s%s", rtsp_message, "\r\n");
	}
	sprintf(rtsp_message, "%s%s", rtsp_message, "\r\n");
	free(data);

	memcpy(pkt, rtsp_message, strlen(rtsp_message)+1);
	*pkt_len = strlen(rtsp_message);

	PJ_LOG(4, (THIS_FILE, " New RTSP message %s", 
		rtsp_message));

	return PJ_SUCCESS;
}

/************************************************************************/
/* Destroy related udp session                                          */
/************************************************************************/
int rtsp_handle_teardown_request(client_t *c, void *pkt, int *pkt_len) {
	return client_rtsp_teardown_session(c);;
}