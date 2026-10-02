#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <config.h>
//charles debug
#include "getopt.h"
#include "natnl_lib.h"
#include "config.h"
//#if !defined(NATNL_LIB)
char callee[128], registrar_uri[128], device_id_to_call[128] = {0};
//#endif
//charles debug

#if PJ_ANDROID==1
#include <errno.h>
#include <j_log.h>
#define THIS_FILE "config.c"
#else
#define LOG_E(x, ...)
#endif

#define PJSUA_MAX_CALLS			15

enum natnl_file_access
{
    NATNL_O_RDONLY     = 0x1101,   /**< Open file for reading.             */
    NATNL_O_WRONLY     = 0x1102,   /**< Open file for writing.             */
    NATNL_O_RDWR       = 0x1103,   /**< Open file for reading and writing. 
                                     File will be truncated.            */
	NATNL_O_APPEND     = 0x1108,    /**< Append to existing file.           */
	NATNL_O_SYSLOG     = 0x1110     /**< Write to sys log.           */
};

/*
 * Read command arguments from config file.
 */
int my_read_config_file(const char *filename, 
			    int *app_argc, char ***app_argv)
{
    int i;
    FILE *fhnd;
    char line[200];
    int argc = 0;
    char **argv;
    enum { MAX_ARGS = 128 };


    /* Allocate MAX_ARGS+1 (argv needs to be terminated with NULL argument) */
    argv = (char **)calloc(MAX_ARGS+1, sizeof(char*));
    argv[argc++] = *app_argv[0];

    /* Open config file. */
    fhnd = fopen(filename, "rt");
    if (!fhnd) {
	printf("Unable to open config file %s", filename);
	fflush(stdout);
	return -1;
    }

    /* Scan tokens in the file. */
    while (argc < MAX_ARGS && !feof(fhnd)) {
	char  *token;
	char  *p;
	const char *whitespace = " \t\r\n";
	char  cDelimiter;
	int   len, token_len;
	
	if (fgets(line, sizeof(line), fhnd) == NULL) break;
	
	// Trim ending newlines
	len = strlen(line);
	if (line[len-1]=='\n')
	    line[--len] = '\0';
	if (line[len-1]=='\r')
	    line[--len] = '\0';

	if (len==0) continue;

	for (p = line; *p != '\0' && argc < MAX_ARGS; p++) {
	    // first, scan whitespaces
	    while (*p != '\0' && strchr(whitespace, *p) != NULL) p++;

	    if (*p == '\0')		    // are we done yet?
		break;
	    
	    if (*p == '"' || *p == '\'') {    // is token a quoted string
		cDelimiter = *p++;	    // save quote delimiter
		token = p;
		
		while (*p != '\0' && *p != cDelimiter) p++;
		
		if (*p == '\0')		// found end of the line, but,
		    cDelimiter = '\0';	// didn't find a matching quote

	    } else {			// token's not a quoted string
		token = p;
		
		while (*p != '\0' && strchr(whitespace, *p) == NULL) p++;
		
		cDelimiter = *p;
	    }
	    
	    *p = '\0';
	    token_len = p-token;
	    
	    if (token_len > 0) {
		if (*token == '#')
		    break;  // ignore remainder of line
		
		argv[argc] = (char *)calloc(token_len + 1, sizeof(char *));
		memcpy(argv[argc], token, token_len + 1);
		++argc;
	    }
	    
	    *p = cDelimiter;
	}
    }

    /* Copy arguments from command line */
    for (i=1; i<*app_argc && argc < MAX_ARGS; ++i)
	argv[argc++] = (*app_argv)[i];

    if (argc == MAX_ARGS && (i!=*app_argc || !feof(fhnd))) {
	printf("Too many arguments specified in cmd line/config file");
	fflush(stdout);
	fclose(fhnd);
	return -1;
    }

    fclose(fhnd);

    /* Assign the new command line back to the original command line. */
    *app_argc = argc;
    *app_argv = argv;
    return 0;

}


/* Parse arguments. */
int my_parse_args(int argc, char *argv[],
					struct natnl_config *natnl_cfg,
					int *tnl_port_count,
					natnl_tnl_port tnl_port_cfg[],
					int *im_port_count,
					natnl_im_port im_port_cfg[])
{
    int c;
    int option_index;
    enum { OPT_CONFIG_FILE=127, OPT_LOG_FILE, OPT_LOG_LEVEL, OPT_APP_LOG_LEVEL, 
	   OPT_LOG_APPEND, OPT_LOG_SYSLOG, OPT_SYSLOG_FACILITY, OPT_LOG_FILE_SIZE, 
	   OPT_LOG_ROTATE_NUMBER, OPT_LOG_FLAG_FILE, OPT_DISABLE_CONSOLE_LOG, 
	   OPT_DEVICE_ID, OPT_DEVICE_PWD, OPT_CALLEE_ID, 
	   OPT_SIP_SRV, OPT_STUN_SRV, OPT_TURN_SRV, OPT_TURN_USR, OPT_TURN_PWD,
       OPT_FORCE_TO_USE_ICE, OPT_USE_TURN, OPT_TUNNEL_LPORT, OPT_TUNNEL_RPORT,
	   OPT_TUNNEL_PORT, OPT_USE_UPNP, OPT_USE_STUN, OPT_USER_PORT, OPT_MAX_CALLS, 
	   OPT_USE_TLS, OPT_TLS_VERIFY_SERVER, OPT_TNL_TIMEOUT_SEC, OPT_VERSION, 
	   OPT_DISABLE_SDP_COMPRESS, OPT_BANDWIDTH_KBS_LIMIT, OPT_IS_SERVER_SIDE_APP,
	   OPT_IDLE_TIMEOUT_SEC, OPT_FAST_INIT, OPT_ENABLE_SECURE_DATA, OPT_CERT, 
	   OPT_CERT_PKEY, OPT_TRUSTED_CA_CERTS, OPT_VERIFY_SERVER_PEER, OPT_USE_SCTP,
	   OPT_IM_PORT, OPT_SIP_TRUSTED_CA_CERTS, OPT_SIP_VERIFY_SERVER_PEER
    };
//	struct pj_getopt_option long_options[32];
	struct pj_getopt_option long_options[] = {	
	{ "config-file",1, 0, OPT_CONFIG_FILE},
	{ "log-file",	1, 0, OPT_LOG_FILE},
	{ "log-level",	1, 0, OPT_LOG_LEVEL},
	{ "app-log-level",1,0,OPT_APP_LOG_LEVEL},
	{ "log-to-syslog",	0, 0, OPT_LOG_SYSLOG},
	{ "syslog-facility",1, 0, OPT_SYSLOG_FACILITY},
	{ "log-append", 0, 0, OPT_LOG_APPEND},
	{ "log-file-size",	1, 0, OPT_LOG_FILE_SIZE},
	{ "log-rotate-number",	1, 0, OPT_LOG_ROTATE_NUMBER},
	{ "log-flag-file",	1, 0, OPT_LOG_FLAG_FILE},
	{ "disable-console-log",	0, 0, OPT_DISABLE_CONSOLE_LOG},
	{ "device-id",	1, 0, OPT_DEVICE_ID},
	{ "device-pwd",	1, 0, OPT_DEVICE_PWD},
	{ "callee-id",	1, 0, OPT_CALLEE_ID},
	{ "sip-srv",		1, 0, OPT_SIP_SRV},
	{ "stun-srv",	1, 0, OPT_STUN_SRV},
	{ "force-to-use-ice",	0, 0, OPT_FORCE_TO_USE_ICE},
	{ "use-turn",	1, 0, OPT_USE_TURN},
	{ "turn-srv",	1, 0, OPT_TURN_SRV},
	{ "turn-usr",	1, 0, OPT_TURN_USR},
	{ "turn-pwd",	1, 0, OPT_TURN_PWD},
	{ "tunnel-lport",	1, 0, OPT_TUNNEL_LPORT},
	{ "tunnel-rport",	1, 0, OPT_TUNNEL_RPORT},
	{ "tunnel-port",	1, 0, OPT_TUNNEL_PORT},
	{ "use-upnp",  1, 0, OPT_USE_UPNP},
	{ "use-stun",  0, 0, OPT_USE_STUN},
	{ "user-port",  1, 0, OPT_USER_PORT},
	{ "max-calls",	1, 0, OPT_MAX_CALLS},
	{ "use-tls",	0, 0, OPT_USE_TLS}, 
	{ "tls-verify-server", 0, 0, OPT_TLS_VERIFY_SERVER},
	{ "tunnel-timeout",	1, 0, OPT_TNL_TIMEOUT_SEC},
	{ "version",	2, 0, OPT_VERSION},
	{ "disable-sdp-compress",	0, 0, OPT_DISABLE_SDP_COMPRESS},
	{ "bandwidth-KBs-limit",	1, 0, OPT_BANDWIDTH_KBS_LIMIT},
	{ "is-server-side-app",	0, 0, OPT_IS_SERVER_SIDE_APP},
	{ "idle-timeout",	1, 0, OPT_IDLE_TIMEOUT_SEC},
	{ "fast-init",	0, 0, OPT_FAST_INIT},
	{ "enable-secure-data",	0, 0, OPT_ENABLE_SECURE_DATA},
	{ "cert",	1, 0, OPT_CERT},
	{ "cert-pkey",	1, 0, OPT_CERT_PKEY},
	{ "trusted-ca-certs",	1, 0, OPT_TRUSTED_CA_CERTS},
	{ "verify-server-peer",	0, 0, OPT_VERIFY_SERVER_PEER},
	{ "use-sctp",	0, 0, OPT_USE_SCTP},
	{ "im-port",	1, 0, OPT_IM_PORT},
	{ "sip-trusted-ca-certs",	1, 0, OPT_SIP_TRUSTED_CA_CERTS},
	{ "sip-verify-server-peer",	1, 0, OPT_SIP_VERIFY_SERVER_PEER},
	{ "im-port",	1, 0, OPT_IM_PORT},
	{ NULL, 0, 0, 0}
    };
    int status;
	char *config_file = NULL;
	int i;

    /* Run pj_getopt once to see if user specifies config file to read. */ 
    pj_optind = 0;
    while ((c=pj_getopt_long(argc, argv, "", long_options, 
			     &option_index)) != -1) 
    {
	switch (c) {
	case OPT_CONFIG_FILE:
	    config_file = pj_optarg;
	    break;
	}
	if (config_file)
	    break;
    }

    if (config_file) {
	status = my_read_config_file(config_file, &argc, &argv);
	if (status != 0)
	    return status;
    }

    //cfg->acc_cnt = 0;
    //cur_acc = &cfg->acc_cfg[0];

    // assign default value first
    strcpy(natnl_cfg->device_id, DEV_ID1);
    strcpy(natnl_cfg->device_pwd, DEV_ID1);
    strcpy(callee, DEV_ID2);
	natnl_cfg->sip_srv_cnt = 0;
    strcpy(natnl_cfg->sip_srv[0], SIP_SERVER);
	sprintf(registrar_uri, "sip:%s", natnl_cfg->sip_srv[0]);
	natnl_cfg->stun_srv_cnt = 0;
	strcpy(natnl_cfg->stun_srv[0], STUN_SERVER);
	natnl_cfg->log_cfg.log_level = 4;
	memset(natnl_cfg->log_cfg.log_filename, 0, 
		sizeof(natnl_cfg->log_cfg.log_filename));
	natnl_cfg->log_cfg.log_file_flags = 0;
	natnl_cfg->log_cfg.syslog_facility = 0;
	natnl_cfg->log_cfg.log_file_size = 0;
	natnl_cfg->log_cfg.log_rotate_number = 0;
	natnl_cfg->log_cfg.disable_console_log = 0;
	memset(natnl_cfg->log_cfg.log_flag_file, 0, 
		sizeof(natnl_cfg->log_cfg.log_flag_file));
#if 0
	strcpy(natnl_cfg->turn_usr, TURN_USR);
    strcpy(natnl_cfg->turn_pwd, TURN_PWD);
#endif
	natnl_cfg->force_to_use_ice = 0;
	natnl_cfg->turn_srv_cnt = 0;
    natnl_cfg->use_turn = 0;
	*tnl_port_count = 0;
	strcpy(tnl_port_cfg[0].lport, "5555");
	strcpy(tnl_port_cfg[0].rport, "8000");
	natnl_cfg->upnp_cfg.flag = 0;
	natnl_cfg->upnp_cfg.user_port_count = 0;
	strcpy(natnl_cfg->upnp_cfg.user_ports[0].local_data, "4000");
	strcpy(natnl_cfg->upnp_cfg.user_ports[0].external_data, "4000");
	strcpy(natnl_cfg->upnp_cfg.user_ports[0].local_ctl, "4001");
	strcpy(natnl_cfg->upnp_cfg.user_ports[0].external_ctl, "4001");
	natnl_cfg->use_stun = 0;
	natnl_cfg->max_calls = 4;
	natnl_cfg->use_tls = 0;
	natnl_cfg->verify_server = 0;
	natnl_cfg->tnl_timeout_sec = 180;
	natnl_cfg->disable_sdp_compress = 0;
	natnl_cfg->bandwidth_KBs_limit = 0;
	natnl_cfg->is_server_side_app = 0;
	natnl_cfg->idle_timeout_sec = 0;
	natnl_cfg->fast_init = 0;
	natnl_cfg->enable_secure_data = 0;
	strcpy(natnl_cfg->cert, "");
	strcpy(natnl_cfg->cert_pkey, "");
	natnl_cfg->verify_server_peer = 0;
	natnl_cfg->use_sctp = 0;
	*im_port_count = 0;
	strcpy(im_port_cfg[0].lport, "7000");
	strcpy(im_port_cfg[0].rport, "8088");
	memset(natnl_cfg->sip_trusted_ca_certs, 0, 
		sizeof(natnl_cfg->sip_trusted_ca_certs));
	natnl_cfg->sip_verify_server_peer = 0;

    /* Reinitialize and re-run pj_getopt again, possibly with new arguments
     * read from config file.
     */
    pj_optind = 0;
	while((c=pj_getopt_long(argc,argv, "", long_options,&option_index))!=-1) {

		switch (c) {

		case OPT_CONFIG_FILE:
			/* Ignore as this has been processed before */
			break;

		case OPT_LOG_LEVEL:
			c = strtoul(pj_optarg, NULL, 0);
			if (c < 0 || c > 6) {
				printf("[main.c] Error: expecting log-level integer value 0~6\n");
				return -2;
			}
			natnl_cfg->log_cfg.log_level = c;
			printf("[main.c] pars_args natnl_cfg->log_level=%d\n", natnl_cfg->log_cfg.log_level);
			break;

		case OPT_LOG_FILE:
			if (strlen(pj_optarg) > sizeof(natnl_cfg->log_cfg.log_filename)) {
				printf("[main.c] Error: log-filename is too long. limits is %d\n",
					sizeof(natnl_cfg->log_cfg.log_filename));
				return -2;
			}
			strncpy(natnl_cfg->log_cfg.log_filename, pj_optarg, strlen(pj_optarg));
			printf("[main.c] pars_args natnl_cfg->log_filename=%s\n", natnl_cfg->log_cfg.log_filename);
			break;

		case OPT_LOG_APPEND:
			natnl_cfg->log_cfg.log_file_flags |= NATNL_O_APPEND;
			printf("[main.c] pars_args natnl_cfg->log_file_flags=%d\n", natnl_cfg->log_cfg.log_file_flags);
			break;

		case OPT_LOG_SYSLOG:
			natnl_cfg->log_cfg.log_file_flags |= NATNL_O_SYSLOG;
			printf("[main.c] pars_args natnl_cfg->log_file_flags=%d\n", natnl_cfg->log_cfg.log_file_flags);
			break;

		case OPT_SYSLOG_FACILITY:
			c = strtoul(pj_optarg, NULL, 0);
			natnl_cfg->log_cfg.syslog_facility = c;
			printf("[main.c] pars_args natnl_cfg->syslog_facility=%d\n", natnl_cfg->log_cfg.syslog_facility);
			break;

		case OPT_LOG_FILE_SIZE:
			c = strtoul(pj_optarg, NULL, 0);
			natnl_cfg->log_cfg.log_file_size = c;
			printf("[main.c] pars_args natnl_cfg->log_size_limit=%d\n", natnl_cfg->log_cfg.log_file_size);
			break;

		case OPT_LOG_ROTATE_NUMBER:
			c = strtoul(pj_optarg, NULL, 0);
			natnl_cfg->log_cfg.log_rotate_number = c;
			printf("[main.c] pars_args natnl_cfg->log_rotate_number=%d\n", natnl_cfg->log_cfg.log_rotate_number);
			break;

		case OPT_LOG_FLAG_FILE:
			if (strlen(pj_optarg) > sizeof(natnl_cfg->log_cfg.log_flag_file)) {
				printf("[main.c] Error: log-flag-file is too long. limits is %d\n",
					sizeof(natnl_cfg->log_cfg.log_flag_file));
				return -2;
			}
			strncpy(natnl_cfg->log_cfg.log_flag_file, pj_optarg, strlen(pj_optarg));
			break;

		case OPT_DISABLE_CONSOLE_LOG:
			natnl_cfg->log_cfg.disable_console_log = 1;
			printf("[main.c] pars_args natnl_cfg->disable_console_log=%d\n", natnl_cfg->log_cfg.disable_console_log);
			break;

		case OPT_DEVICE_ID:
			strcpy(natnl_cfg->device_id, pj_optarg);
			//sprintf(registrar_uri, "sip:%s", natnl_cfg->sip_srv);
			printf("[main.c] pars_args natnl_cfg->device_id=%s\n", natnl_cfg->device_id);
			break;

		case OPT_DEVICE_PWD:
			strcpy(natnl_cfg->device_pwd, pj_optarg);
			printf("[main.c] pars_args natnl_cfg->device_pwd=%s\n", natnl_cfg->device_pwd);
			break;

		case OPT_CALLEE_ID:
			strcpy(callee, pj_optarg);
			printf("[main.c] pars_args natnl_cfg->callee_id=%s\n", callee);
			break;

		case OPT_SIP_SRV:
			if (natnl_cfg->sip_srv_cnt < MAX_SIP_SERVER_COUNT) {
				strcpy(natnl_cfg->sip_srv[natnl_cfg->sip_srv_cnt], pj_optarg);
				sprintf(registrar_uri, "sip:%s", natnl_cfg->sip_srv[natnl_cfg->sip_srv_cnt]);
				printf("[main.c] pars_args natnl_cfg->sip_srv[%d]=%s\n", 
					natnl_cfg->sip_srv_cnt, natnl_cfg->sip_srv[natnl_cfg->sip_srv_cnt]);
				natnl_cfg->sip_srv_cnt++;
			}
			break;

		case OPT_STUN_SRV:
			if (natnl_cfg->stun_srv_cnt < MAX_STUN_SERVER_COUNT) {
				strcpy(natnl_cfg->stun_srv[natnl_cfg->stun_srv_cnt], pj_optarg);
				printf("[main.c] pars_args natnl_cfg->stun_srv[%d]=%s\n", 
					natnl_cfg->stun_srv_cnt, natnl_cfg->stun_srv[natnl_cfg->stun_srv_cnt]);
				natnl_cfg->stun_srv_cnt++;
			}
			break;

		case OPT_FORCE_TO_USE_ICE:
			natnl_cfg->force_to_use_ice = 1;
			printf("[main.c] pars_args natnl_cfg->force_to_use_ice=true\n");
			break;

		case OPT_USE_TURN:
			c = strtoul(pj_optarg, NULL, 0);
			if (c < 0 || c > 7) {
				printf("[main.c] Error: expecting use-turn integer value 0~2\n");
				return -2;
			}
			natnl_cfg->use_turn = c;
			printf("[main.c] pars_args natnl_cfg->use_turn=%d\n", natnl_cfg->use_turn);
			break;

		case OPT_TURN_SRV:
			if (natnl_cfg->turn_srv_cnt < MAX_TURN_SERVER_COUNT) {
				strcpy(natnl_cfg->turn_srv[natnl_cfg->turn_srv_cnt], pj_optarg);
				printf("[main.c] pars_args natnl_cfg->turn_srv[%d]=%s\n", 
					natnl_cfg->turn_srv_cnt, natnl_cfg->turn_srv[natnl_cfg->turn_srv_cnt]);
				natnl_cfg->turn_srv_cnt++;
			}
			break;

#if 0
		case OPT_TURN_USR:
			strcpy(natnl_cfg->turn_usr, pj_optarg);
			printf("[main.c] pars_args natnl_cfg->turn_usr=%s\n", natnl_cfg->turn_usr);
			break;

		case OPT_TURN_PWD:
			strcpy(natnl_cfg->turn_pwd, pj_optarg);
			printf("[main.c] pars_args natnl_cfg->turn_pwd=%s\n", natnl_cfg->turn_pwd);
			break;
#endif

		case OPT_TUNNEL_LPORT:
			strcpy(tnl_port_cfg[0].lport, pj_optarg);
			printf("[main.c] pars_args tnl_port_cfg[0]->lport=%s\n", tnl_port_cfg[0].lport);
			break;

		case OPT_TUNNEL_RPORT:
			strcpy(tnl_port_cfg[0].rport, pj_optarg);
			printf("[main.c] pars_args tnl_port_cfg[0]->rport=%s\n", tnl_port_cfg[0].rport);
			break;

		case OPT_TUNNEL_PORT:
			if (*tnl_port_count < MAX_TUNNEL_PORT_COUNT) {
				char *lport, *rport, *qos_priority, *didable_flow_control, *speed_limit, *rip;
				lport = strtok(pj_optarg, ",");
				if (lport == NULL) {
					printf("Argument \"%s\" is not valid. The format is [lport,rport[,qos_priority]]",
						  argv[pj_optind-1]);
					return -1;
				}

				rport = strtok(NULL, ",");
				if (rport == NULL) {
					printf("Argument \"%s\" is not valid. The format is [lport,rport[,qos_priority]]",
						argv[pj_optind-1]);
					return -1;
				}
				strcpy(tnl_port_cfg[*tnl_port_count].lport, lport);
				strcpy(tnl_port_cfg[*tnl_port_count].rport, rport);

				qos_priority = strtok(NULL, ",");				
				if (qos_priority)
					tnl_port_cfg[*tnl_port_count].qos_priority = atoi(qos_priority);
				else
					tnl_port_cfg[*tnl_port_count].qos_priority = 0;

				didable_flow_control = strtok(NULL, ",");
				if (didable_flow_control)
					tnl_port_cfg[*tnl_port_count].disable_flow_control = atoi(didable_flow_control);
				else
					tnl_port_cfg[*tnl_port_count].disable_flow_control = 0;

				speed_limit = strtok(NULL, ",");
				if (speed_limit)
					tnl_port_cfg[*tnl_port_count].speed_limit = atoi(speed_limit);
				else
					tnl_port_cfg[*tnl_port_count].speed_limit = 0;

				rip = strtok(NULL, ",");
				memset(tnl_port_cfg[*tnl_port_count].rip, 0, sizeof(tnl_port_cfg[*tnl_port_count].rip));
				if (rip)
					strcpy(tnl_port_cfg[*tnl_port_count].rip, rip);

				printf("[main.c] pars_args tnl_port_cfg[%d]->lport=%s, tnl_port_cfg[%d]->rport=%s, tnl_port_cfg[%d]->qos_priority=%d, tnl_port_cfg[%d]->disable_flow_control=%d, tnl_port_cfg[%d]->speed_limit=%d, tnl_port_cfg[%d]->rip=%s\n", 
					*tnl_port_count, tnl_port_cfg[*tnl_port_count].lport, 
					*tnl_port_count, tnl_port_cfg[*tnl_port_count].rport, 
					*tnl_port_count, tnl_port_cfg[*tnl_port_count].qos_priority, 
					*tnl_port_count, tnl_port_cfg[*tnl_port_count].disable_flow_control, 
					*tnl_port_count, tnl_port_cfg[*tnl_port_count].speed_limit, 
					*tnl_port_count, tnl_port_cfg[*tnl_port_count].rip);
				(*tnl_port_count)++;
			}
			break;

		case OPT_USE_UPNP:
			c = strtoul(pj_optarg, NULL, 0);
			if (c < 0 || c > 2) {
				printf("[main.c] Error: expecting upnp-flag integer value 0~2\n");
				return -2;
			}
			natnl_cfg->upnp_cfg.flag = c;
			printf("[main.c] pars_args natnl_cfg->upnp_cfg.flag=%d\n", natnl_cfg->upnp_cfg.flag);
			break;

		case OPT_USE_STUN:
			natnl_cfg->use_stun = 1;
			printf("[main.c] pars_args natnl_cfg->use_stun=true\n");
			break;

		case OPT_USER_PORT:
			if (natnl_cfg->upnp_cfg.user_port_count < MAX_USER_PORT_COUNT) {
				char *data_port, *ctl_port, 
					*local_data_port, *external_data_port,
					*local_ctl_port, *external_ctl_port;
				local_data_port = strtok(pj_optarg, ",");
				if (local_data_port == NULL) {
					printf("Argument \"%s\" is not valid. The format is [data_port_pair,control_port_pair]",
						argv[pj_optind-1]);
					return -1;
				}
#if 1
				external_data_port = strtok(NULL, ",");
				if (external_data_port == NULL) {
					printf("Argument \"%s\" is not valid. The format is [data_port_pair,control_port_pair]",
						argv[pj_optind-1]);
					return -1;
				}
#else
				ctl_port = strtok(NULL, ",");
				if (ctl_port == NULL) {
					printf("Argument \"%s\" is not valid. The format is [data_port_pair,control_port_pair]",
						argv[pj_optind-1]);
					return -1;
				}
				local_data_port = strtok(data_port, "-");
				if (local_data_port == NULL) {
					printf("Argument \"%s\" is not valid. The data_port format is [local_data_port-external_data_port]",
						argv[pj_optind-1]);
					return -1;
				}

				external_data_port = strtok(data_port, "-");
				if (external_data_port == NULL) {
					printf("Argument \"%s\" is not valid. The data_port format is [local_data_port-external_data_port]",
						argv[pj_optind-1]);
					return -1;
				}
				local_ctl_port = strtok(ctl_port, "-");
				if (local_ctl_port == NULL) {
					printf("Argument \"%s\" is not valid. The ctl_port format is [local_ctl_port-external_ctl_port]",
						argv[pj_optind-1]);
					return -1;
				}

				external_ctl_port = strtok(ctl_port, "-");
				if (external_ctl_port == NULL) {
					printf("Argument \"%s\" is not valid. The ctl_port format is [local_ctl_port-external_ctl_port]",
						argv[pj_optind-1]);
					return -1;
				}
#endif

				strcpy(natnl_cfg->upnp_cfg.user_ports[natnl_cfg->upnp_cfg.user_port_count].local_data, local_data_port);
				strcpy(natnl_cfg->upnp_cfg.user_ports[natnl_cfg->upnp_cfg.user_port_count].external_data, external_data_port);
				strcpy(natnl_cfg->upnp_cfg.user_ports[natnl_cfg->upnp_cfg.user_port_count].local_ctl, "");
				strcpy(natnl_cfg->upnp_cfg.user_ports[natnl_cfg->upnp_cfg.user_port_count].external_ctl, "");
				printf("[main.c] pars_args natnl_cfg->upnp_cfg.user_ports[%d]->local_data=%s, "
					"natnl_cfg->upnp_cfg.user_ports[%d]->extenal_data=%s\n", 
					natnl_cfg->upnp_cfg.user_port_count, 
					natnl_cfg->upnp_cfg.user_ports[natnl_cfg->upnp_cfg.user_port_count].local_data, 
					natnl_cfg->upnp_cfg.user_port_count, 
					natnl_cfg->upnp_cfg.user_ports[natnl_cfg->upnp_cfg.user_port_count].external_data);
				printf("[main.c] pars_args natnl_cfg->upnp_cfg.user_ports[%d]->local_ctl=%s, "
					"natnl_cfg->upnp_cfg.user_ports[%d]->extenal_ctl=%s\n", 
					natnl_cfg->upnp_cfg.user_port_count, 
					natnl_cfg->upnp_cfg.user_ports[natnl_cfg->upnp_cfg.user_port_count].local_ctl, 
					natnl_cfg->upnp_cfg.user_port_count, 
					natnl_cfg->upnp_cfg.user_ports[natnl_cfg->upnp_cfg.user_port_count].external_ctl);
				(natnl_cfg->upnp_cfg.user_port_count)++;
			}
			break;

		case OPT_MAX_CALLS:
			c = strtoul(pj_optarg, NULL, 0);
			if (c < 1 || c > PJSUA_MAX_CALLS) {				
				printf("Argument \"%s\" is not valid. compile time limit (PJSUA_MAX_CALLS=%d)",
					argv[pj_optind-1], PJSUA_MAX_CALLS);
				return -1;
			}
			natnl_cfg->max_calls = c;
			break;

		case OPT_USE_TLS:
			natnl_cfg->use_tls = 1;
			printf("[main.c] pars_args natnl_cfg->tls.use_tls=true\n");
			break;

		case OPT_TLS_VERIFY_SERVER:
			natnl_cfg->verify_server = 1;
			printf("[main.c] pars_args natnl_cfg->tls.verify_server=true\n");
			break;

		case OPT_TNL_TIMEOUT_SEC:
			c = strtoul(pj_optarg, NULL, 0);
			if (c < 0 || c > 180) {				
				printf("Argument \"%s\" is not valid. compile time limit (MAX_TNL_TIMEOUT_SEC=%d)",
					argv[pj_optind-1], 180);
				return -1;
			}
			natnl_cfg->tnl_timeout_sec = c;
			break;

		case OPT_DISABLE_SDP_COMPRESS:
			natnl_cfg->disable_sdp_compress = 1;
			printf("[main.c] pars_args natnl_cfg->disable_sdp_compress=true\n");
			break;

		case OPT_VERSION:
			/* Do nothing */
			break;

		case OPT_BANDWIDTH_KBS_LIMIT:
			natnl_cfg->bandwidth_KBs_limit = strtoul(pj_optarg, NULL, 0);
			printf("[main.c] pars_args natnl_cfg->bandwidth_kb_limit=%d\n", natnl_cfg->bandwidth_KBs_limit);
			break;

		case OPT_IS_SERVER_SIDE_APP:
			natnl_cfg->is_server_side_app = 1;
			printf("[main.c] pars_args natnl_cfg->is_server_side_app=%d\n", natnl_cfg->is_server_side_app);
			break;

		case OPT_IDLE_TIMEOUT_SEC:
			c = strtoul(pj_optarg, NULL, 0);
			if (c < 0) {				
				printf("Argument \"%s\" is not valid. This must be >=0");
				return -1;
			}
			natnl_cfg->idle_timeout_sec = c;
			break;

		case OPT_FAST_INIT:
			natnl_cfg->fast_init = 1;
			printf("[main.c] pars_args natnl_cfg->fast_init=%d\n", natnl_cfg->fast_init);
			break;

		case OPT_ENABLE_SECURE_DATA:
			natnl_cfg->enable_secure_data = 1;
			printf("[main.c] pars_args natnl_cfg->enable_secure_data=%d\n", natnl_cfg->enable_secure_data);
			break;

		case OPT_CERT:
			strcpy(natnl_cfg->cert, pj_optarg);
			printf("[main.c] pars_args natnl_cfg->cert=%s\n", natnl_cfg->cert);
			break;

		case OPT_CERT_PKEY:
			strcpy(natnl_cfg->cert_pkey, pj_optarg);
			printf("[main.c] pars_args natnl_cfg->cert_pkey=%s\n", natnl_cfg->cert_pkey);
			break;

		case OPT_TRUSTED_CA_CERTS:
			strcpy(natnl_cfg->trusted_ca_certs, pj_optarg);
			printf("[main.c] pars_args natnl_cfg->truested_ca_certs=%s\n", natnl_cfg->trusted_ca_certs);
			break;

		case OPT_VERIFY_SERVER_PEER:
			natnl_cfg->verify_server_peer = 1;
			printf("[main.c] pars_args natnl_cfg->verify_server_peer=%d\n", natnl_cfg->verify_server_peer);
			break;

		case OPT_USE_SCTP:
			natnl_cfg->use_sctp = 1;
			printf("[main.c] pars_args natnl_cfg->use_sctp=%d\n", natnl_cfg->use_sctp);
			break;

		case OPT_IM_PORT:
			if (*im_port_count < MAX_TUNNEL_PORT_COUNT) {
				char *dest_device_id, *lport, *rport, *timeout;
				dest_device_id = strtok(pj_optarg, ",");
				if (dest_device_id == NULL) {
					printf("Argument \"%s\" is not valid. The format is [dest_device_id,lport,rport,timeout]",
						argv[pj_optind-1]);
					return -1;
				}

				lport = strtok(NULL, ",");
				if (lport == NULL) {
					printf("Argument \"%s\" is not valid. The format is [dest_device_id,lport,rport,timeout]",
						argv[pj_optind-1]);
					return -1;
				}

				rport = strtok(NULL, ",");
				if (rport == NULL) {
					printf("Argument \"%s\" is not valid. The format is [dest_device_id,lport,rport,timeout]",
						argv[pj_optind-1]);
					return -1;
				}
				strcpy(im_port_cfg[*im_port_count].dest_device_id, dest_device_id);
				strcpy(im_port_cfg[*im_port_count].lport, lport);
				strcpy(im_port_cfg[*im_port_count].rport, rport);

				timeout = strtok(NULL, ",");
				if (timeout == NULL) {
					printf("Argument \"%s\" is not valid. The format is [dest_device_id,lport,rport,timeout]",
						argv[pj_optind-1]);
					return -1;
				}
				im_port_cfg[*im_port_count].timeout_sec = atoi(timeout);

				printf("[main.c] pars_args im_port_cfg[%d]->dest_device_id=%s, im_port_cfg[%d]->lport=%s, im_port_cfg[%d]->rport=%s, im_port_cfg[%d]->timeout_sec=%d\n", 
					*im_port_count, im_port_cfg[*im_port_count].dest_device_id, 
					*im_port_count, im_port_cfg[*im_port_count].lport, 
					*im_port_count, im_port_cfg[*im_port_count].rport, 
					*im_port_count, im_port_cfg[*im_port_count].timeout_sec);
				(*im_port_count)++;
			}
			break;

		case OPT_SIP_TRUSTED_CA_CERTS:
			strcpy(natnl_cfg->sip_trusted_ca_certs, pj_optarg);
			printf("[main.c] pars_args natnl_cfg->sip_trusted_ca_certs=%s\n", natnl_cfg->sip_trusted_ca_certs);
			break;

		case OPT_SIP_VERIFY_SERVER_PEER:
			natnl_cfg->sip_verify_server_peer = 1;
			printf("[main.c] pars_args natnl_cfg->sip_verify_server_peer=%d\n", natnl_cfg->sip_verify_server_peer);
			break;

		default:
			printf("Argument \"%s\" is not valid. Use --help to see help\n",
				  argv[pj_optind-1]);
			return -1;
		}
	}

	// 2013-03-20 DEAN Added, parsing device id to call if any.
	if (pj_optind != argc) {
		char* uri_arg;

		uri_arg = argv[pj_optind];
		memcpy(device_id_to_call, uri_arg, strlen(uri_arg));
		pj_optind++;
	}

	if (!(*tnl_port_count))
		*tnl_port_count = 1;

	free(argv);

    return 0;
}
