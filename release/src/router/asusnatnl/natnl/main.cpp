#ifdef WIN32
#include <vld.h>
#endif
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjmedia.h>
#include <pjmedia-codec.h>
#include <pjsip.h>
#include <pjsip_simple.h>
#include <pjsip_ua.h>
#include <pj/string.h>	    /* pj_memcpy(), pj_memset() */
	
// We will rewrite our own pjsua in future
#include <pjsua-lib/pjsua.h>
#include <pjsua-lib/pjsua_internal.h>
#include <pjmedia/natnl_stream.h>
#include <pjnath/natnl_tnl_cache.h>
#include <natnl.h>
#include <natnl_codec.h>
#include <message.h>
#include <client.h>
#include <natnl_lib.h>
#include <udt.h>
#include "im_handler.h"
#include "im_ipc.h"

#if !defined(PJMEDIA_DISABLE_SCTP) || (PJMEDIA_DISABLE_SCTP==0) // sctp disabled
#include <usrsctp.h>
#endif

//Natnl version
#include <version.h>

#define THIS_FILE "natnl/main.c"
#define DETECT_TIMEOUT 10000		// 10 sec

PJ_DEF_DATA(const char*) tnl_version = NATNL_VERSION;
const char* natnl_get_version(void)
{
    return NATNL_VERSION;
}

#if defined(PJ_LINUX)
#include <signal.h>

static void sig_handler(int sig, siginfo_t *siginfo, void *context)
{
	PJ_LOG(4, (THIS_FILE, "Sending PID=[%ld], UID=[%ld], addr=[%p]\n",
		(long)siginfo->si_pid, (long)siginfo->si_uid, siginfo->si_addr));
}

static void setup_action_signal() 
{
	struct sigaction act;

	memset (&act, '\0', sizeof(act));

	/* Use the sa_sigaction field because the handles has two additional parameters */
	act.sa_sigaction = &sig_handler;

	/* The SA_SIGINFO flag tells sigaction() to use the sa_sigaction field, not sa_handler. */
	act.sa_flags = SA_SIGINFO;

	if (sigaction(SIGTERM, &act, NULL) < 0) {
		perror ("sigaction SIGTERM");
		return;
	}

	if (sigaction(SIGABRT, &act, NULL) < 0) {
		perror ("sigaction SIGTABRT");
		return;
	}

	if (sigaction(SIGSEGV, &act, NULL) < 0) {
		perror ("sigaction SIGTSEGV");
		return;
	}

	if (sigaction(SIGBUS, &act, NULL) < 0) {
		perror ("sigaction SIGBUS");
		return;
	}
}
#endif

#if defined(PJ_DARWINOS)
#include <signal.h>




static void setup_signal_handler(void)
{
}

static void setup_socket_signal()
{
	signal(SIGPIPE, SIG_IGN);
}

#endif

//#define USE_PORTAUD0IO

//#define ALLOW_UPDATE_SVR_CFG

#define NO_LIMIT	(int)0x7FFFFFFF

#define ACCOUNT_CNT 1

#define UPNP_PORT_MAPPING 1
#define ENABLE_ICE 0
#define ENABLE_TURN 1
#define CLOUD 1

#define ASUS_UPNP_DESC "ASUS NAT Tunnel"

#if ENABLE_TURN == 1
#define TURN_USR "dean_li@asus.com"
#define TURN_PWD "asus"
#endif

#if CLOUD == 0
#define UA1 "dean01"
#define UA2 "dean02"
#define SIP_SERVER "192.168.123.251"
#define STUN_SERVER "192.168.123.251"
#define TURN_SERVER "192.168.123.251:3488"
#endif

#if CLOUD == 1
#define UA1 "80bd8155a2540ef1e87ea2f811390e5d"
#define UA2 "ab8806d6e27ea16cd8c4557f8cb3179c"
#define SIP_SERVER "ec2-50-17-15-111.compute-1.amazonaws.com"
#define STUN_SERVER "stun.xten.com"
#define TURN_SERVER "numb.viagenie.ca"
#endif

#if CLOUD == 2
#define UA1 "asus01"
#define UA2 "asus02"
#define SIP_SERVER "iptel.org"
#define STUN_SERVER "stun.voip.aebc.com"
#define TURN_SERVER "numb.viagenie.ca"
#endif


enum timer_id
{
	TIMER_ID_NONE,
	TIMER_ID_RE_REGISTER,
	TIMER_ID_CALL_HOLD,
	TIMER_ID_CALL_UNHOLD,
	TIMER_ID_CALL_UAS_ADDR_CHANGED,
	TIMER_ID_CALL_REINVITE,
	TIMER_ID_CALL_DELAY_THREAD,
	TIMER_ID_CALL_RE_CREATE_TRANSPORT
};

#define current_acc(inst_id)	pjsua_acc_get_default(inst_id)

/* static functions */
static void re_reg_func(pj_timer_heap_t *th, struct pj_timer_entry *te);

/* static functions */
static void re_inv_func(pj_timer_heap_t *th, struct pj_timer_entry *te);

/* external functions */

//extern PJ_DEF(pj_status_t) natnl_logging_endpt_create(pjsua_inst_id inst_id,
//													  const pjsua_logging_config *log_cfg);

//extern PJ_DEF(pj_status_t) natnl_create(pjsua_inst_id inst_id);


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
extern natnl_status_code tunnel_srv_socket_destroy(pjsua_inst_id inst_id,
												   pjsua_call_id call_id, 
												char *lport, char *rport);
extern int tunnel_init(pjsua_inst_id inst_id, pjsua_call_id call_id, int bandwidth_limit);
extern int udpserver_init(pjsua_call_id call_id);
extern int udpserver_init(pjsua_call_id call_id);
extern int tunnel_destroy(pjsua_inst_id inst_id, pjsua_call_id call_id);
extern int udpserver_destroy(pjsua_call_id call_id);
extern int udpserver_destroy(pjsua_call_id call_id);

extern int natnl_recv_thread(void *arg);


static int curr_instances = 1;  // Current number of instances.

static int deinit_lib(int inst_id);

void printVersion(void);
 
struct inv_info {
	pjsua_inst_id inst_id;
	pjsua_call_id call_id;
	char dest_uri[128];
};

/* Pjsua application data */
static struct app_config
{
	pjsua_config			cfg;
	pjsua_logging_config	log_cfg;
	pjsua_media_config		media_cfg;
	pj_bool_t				no_refersub;
	pj_bool_t				ipv6;
	pj_bool_t				enable_qos;
	pj_bool_t				no_tcp;
	pj_bool_t				no_udp;
	pj_bool_t				use_tls;
	pj_bool_t				use_ice;
	pjsua_transport_config  udp_cfg;
	pjsua_transport_config  rtp_cfg;
	pjsip_redirect_op		redir_op;

	unsigned				acc_cnt;
	pjsua_acc_config		acc_cfg[PJSUA_MAX_ACC];

	unsigned				buddy_cnt;
	pjsua_buddy_config	    buddy_cfg[PJSUA_MAX_BUDDIES];

	struct call_data		call_data[PJSUA_MAX_CALLS];

	pj_bool_t				auto_play_hangup;
	unsigned				auto_answer;
	unsigned				duration;

    int						capture_dev, playback_dev;
    pj_pool_t				*snd_pool;  /**< Sound's private pool.		*/
    pjmedia_snd_port		*snd_port;  /**< Sound port.			*/
    pjmedia_port			*null_port; /**< Null port.			*/
    pjmedia_master_port	*null_snd;  /**< Master port for null sound.	*/
    //pj_timer_entry			snd_idle_timer;/**< Sound device idle timer.	*/

	pj_stun_nat_type		nat_type;
	pj_bool_t				nat_type_detected;
	char                    nat_type_name[16];
	pj_bool_t               use_nat_codec;
	int 					use_upnp_flag; // 0 : don't use upnp, 1 : use upnp with SDK selected port, 2 : use user selected port
	pj_bool_t				use_stun_cand;
	int 					use_turn_flag; // 0 : don't use turn, 1 : UAC and UAS use respective turn server, 2 : UAC and UAS both use UAC's turn server
	pj_sockaddr_in			stun_local_addr;
	pj_sockaddr_in			stun_mapped_addr;

	int             		upnp_port[PJSUA_MAX_CALLS];

	//Replaced by pjsua_var[].mutex
	//pj_mutex_t              *inited_lock_obj; // for deinit double times lock.

	pj_timestamp			last_ip_changed; // 2013-04-02 DEAN, to prevent duplicate ip changed event.

	pj_bool_t				is_initializing; // 2013-12-04 DEAN, mark SDK is is_initializing
	pj_bool_t				is_deinitializing; // 2013-04-02 DEAN, mark SDK is deinitializing
	pj_bool_t				is_app_invoking_reg; // 2014-07-17 DEAN, mark SDK is is_app_invoking_reg

	pj_timer_entry          tnl_timer_entry;   //2013-06-05 DEAN
	//pj_bool_t				is_one_day_reg_recovery_timer_scheduled;
	pj_timer_entry          one_day_reg_recovery_timer_entry;//2014-02-18 DEAN
	pj_timer_entry          re_reg_timer_entry;//2014-02-18 DEAN
	pj_timer_entry          re_inv_timer_entry[PJSUA_MAX_CALLS];//2014-10-16 DEAN


	pjsua_call_id	current_call;
	char uri_to_be_called[128], account_id[128], 
		 username[128], realm[128], user_id[128], reg_call_id[128];
	char callee_str[128], registrar_uri_str[128];

	pj_bool_t register_only;
	pj_bool_t reg_ok;
	int upnp_port_mapping_cnt;

	pj_bool_t reinvite_mode;
	pj_bool_t hold_mode;
	int reinvite_call_id;

	/*The definition of global variables that are in natnl_dll.h*/
	struct natnl_config natnl_cfg;

	// for auto-recovery use
	int curr_sip_idx;
	int sip_retry_cnt;

	void *app_data;  // store APP's user_data
	void *user_data; // for registration result waiting.

	struct inv_info re_inv_info[PJSUA_MAX_CALLS]; // re-invite info include inst_id, call_id and dest_uri.
	int curr_re_inv_sip_idx[PJSUA_MAX_CALLS]; // current sip which is used to re-invite.
	int sip_re_inv_cnt[PJSUA_MAX_CALLS]; // the count number of re-invite.
	struct natnl_data call_user_data[PJSUA_MAX_CALLS]; // for making call result waiting.

	int call_hangup_request[PJSUA_MAX_CALLS]; // the flag for every call hanging up request is received.

	natnl_list_t *im_lport_socks; // The list of instant message lport server socket.
	natnl_list_t *im_sessions; // The list of instant message session.

	pj_thread_t *im_lport_thread;
	pj_mutex_t *im_lock;
	pj_bool_t im_lport_thread_quit;
	int im_nfds;
	int is_our_product;  // the device is our product

} app_config[PJSUA_MAX_INSTANCES];

// DEAN reconfig argument functions
static void reconfig_sip_srv(struct app_config *cfg, int inst_id);
static void reconfig_device_id(struct app_config *cfg, int inst_id);
static void reconfig_device_pwd(struct app_config *cfg, int inst_id);
static void reconfig_use_stun(struct app_config *cfg);
static void reconfig_use_turn(struct app_config *cfg);
static void reconfig_use_upnp(struct app_config *cfg);
static void reconfig_turn_srv(struct app_config *cfg, int isnt_id);

#ifdef WIN32
static void __dbg_printf (const char * format,...)
{
#define MAX_DBG_MSG_LEN (1024)
	char buf[MAX_DBG_MSG_LEN];
	va_list ap;

	va_start(ap, format);

	_vsnprintf(buf, sizeof(buf), format, ap);
	OutputDebugStringA(buf);

	va_end(ap);
}
#define DBG __dbg_printf

void log_cb(pjsua_inst_id inst_id, int level, const char *data, int len) {
	//if (level <= pjsua_var[0].log_cfg.level)
		OutputDebugStringA(data);
}
#endif

int update_instant_msg_port(int action, 
							int im_port_cnt, 
							natnl_im_port im_ports[],
							int inst_id) {
	int status;
	int i;

	PJ_LOG(4, (THIS_FILE, "update_instant_msg_port() inst_id=[%d], action=[%d], im_port_cnt=[%d]",
		inst_id, action, im_port_cnt));

	for (i = 0; i < im_port_cnt; i++)
	{
		switch (action)
		{
		case 1:
			status = im_srv_socket_init(inst_id, im_ports[i].dest_device_id, 
				im_ports[i].lport, 
				NULL, 
				im_ports[i].rport, 
				im_ports[i].timeout_sec);
			if (status != PJ_SUCCESS)
				return status;
			break;
		case 2:
			status = im_srv_socket_destroy(inst_id, im_ports[i].lport, im_ports[i].rport);
			if (status != PJ_SUCCESS)
				return status;
			break;
		default:

			return -1; // Unknown action
		}
	}
	return PJ_SUCCESS;
}

PJ_DEF(pj_stun_nat_type) natnl_get_nat_type(int inst_id) {
	return app_config[inst_id].nat_type;
}

PJ_DEF(void *) natnl_get_app_data(int inst_id) {
	return app_config[inst_id].app_data;
}

PJ_DEF(void *) natnl_get_call_user_data(int inst_id, int call_id) {
	return &app_config[inst_id].call_user_data[call_id];
}

PJ_DEF(void *) natnl_get_im_lport_socks(int inst_id) {
	return app_config[inst_id].im_lport_socks;
}

PJ_DEF(void) natnl_set_im_lport_socks(int inst_id, natnl_list_t *im_lport_socks) {
	app_config[inst_id].im_lport_socks = im_lport_socks;
}

PJ_DEF(void *) natnl_get_im_sessions(int inst_id) {
	return app_config[inst_id].im_sessions;
}

PJ_DEF(void) natnl_set_im_sessions(int inst_id, natnl_list_t *im_sessions) {
	app_config[inst_id].im_sessions = im_sessions;
}

PJ_DEF(void *) natnl_get_im_lport_thread(int inst_id) {
	return app_config[inst_id].im_lport_thread;
}

PJ_DEF(void) natnl_set_im_lport_thread(int inst_id, pj_thread_t *thread) {
	app_config[inst_id].im_lport_thread = thread;
}

PJ_DEF(void *) natnl_get_im_lock(int inst_id) {
	return app_config[inst_id].im_lock;
}

PJ_DEF(void) natnl_set_im_lock(int inst_id, pj_mutex_t *lock) {
	app_config[inst_id].im_lock = lock;
}

PJ_DEF(pj_bool_t) natnl_get_im_lport_thread_quit(int inst_id) {
	return app_config[inst_id].im_lport_thread_quit;
}

PJ_DEF(void) natnl_set_im_lport_thread_quit(int inst_id, pj_bool_t quit) {
	app_config[inst_id].im_lport_thread_quit = quit;
}

PJ_DEF(int) natnl_get_im_nfds(int inst_id) {
	return app_config[inst_id].im_nfds;
}

PJ_DEF(void) natnl_set_im_nfds(int inst_id, int nfds) {
	app_config[inst_id].im_nfds = nfds;
}

PJ_DEF(char *) natnl_get_curr_sip_srv(int inst_id) {
	return app_config[inst_id].natnl_cfg.sip_srv[app_config[inst_id].curr_sip_idx];
}

PJ_DEF(void) natnl_set_call_hangup_mode(int inst_id, int call_id, int value) {
	app_config[inst_id].call_hangup_request[call_id] = value;
}

PJ_DEF(struct call_data *) pjsip_get_call_data(pjsua_inst_id inst_id, pjsua_call_id call_id) 
{
	if(call_id >= PJSUA_MAX_CALLS || call_id < 0)
    {
        PJ_LOG(2, (THIS_FILE, "pjsip_get_call_data(). "
                             "call_data=[NULL], call_id=[%d]", 
                   call_id));
		return NULL;
    }

	return &app_config[inst_id].call_data[call_id];
}

PJ_DEF(pjsua_logging_config *) natnl_get_app_config(int inst_id) {
	return &app_config[inst_id].log_cfg;
}

PJ_DEF(pj_pool_t *) pjsip_get_app_pool(int inst_id) 
{
	return pjsua_var[inst_id].pool;
}

PJ_DEF(pj_pool_t *) pjsip_get_stream_pool(int inst_id, int call_id) 
{
	if (pjsua_var[inst_id].calls[call_id].tnl_stream)
		return pjsua_var[inst_id].calls[call_id].tnl_stream->pool;
	else
		return NULL;
}

void pjsip_call_state_machine(pjsua_inst_id inst_id, pjsua_call_id call_id, int state)
{
	PJ_LOG(4, (THIS_FILE, "[call flow] pjsip_call_state_machine()."));

	pjsua_call *call = &pjsua_var[inst_id].calls[call_id];
    pjsua_call_info call_info;
    pjsua_call_get_info(inst_id, call_id, &call_info);

    PJ_LOG(4, (THIS_FILE, "[call flow] pjsip_call_state_machine(). "
                         "call_id=[%d], role=[%d], state=[%d]", 
               call_id, call_info.role, state));

	return;
}

void dump_transport_info(pjsua_call_id call_id)
{
#if 0
//printf("enter dump_transport_info..with call_id=[%d]\n", call_id);
    if (pjsua_var.calls[call_id].med_tp) {
        pjmedia_transport_info tpinfo;
        pjmedia_transport_info_init(&tpinfo);
        pjmedia_transport_get_info(pjsua_var.calls[call_id].med_tp, &tpinfo);

//printf("sock fd: [%d]\n", tpinfo.sock_info.rtp_sock);
ntf("local: %s:%d\n", pj_inet_ntoa(tpinfo.sock_info.rtp_addr_name.ipv4.sin_addr),
                      pj_ntohs(tpinfo.sock_info.rtp_addr_name.ipv4.sin_port));
ntf("from: %s:%d\n",  pj_inet_ntoa(tpinfo.src_rtp_name.ipv4.sin_addr),
                      pj_ntohs(tpinfo.src_rtp_name.ipv4.sin_port));
    }
#endif
    return;
}

/*
 * Find next call when current call is disconnected or when user
 * press ']'
 */
static pj_bool_t find_next_call(pjsua_inst_id inst_id)
{
    int i, max;

    max = pjsua_call_get_max_count(inst_id);
    for (i=app_config[inst_id].current_call+1; i<max; ++i) {
        if (pjsua_call_is_active(inst_id, i)) {
            app_config[inst_id].current_call = i;
            return PJ_TRUE;
        }
    }

    for (i=0; i<app_config[inst_id].current_call; ++i) {
        if (pjsua_call_is_active(inst_id, i)) {
            app_config[inst_id].current_call = i;
            return PJ_TRUE;
        }
    }

    app_config[inst_id].current_call = PJSUA_INVALID_ID;
    return PJ_FALSE;
}


/*
 * Find previous call when user press '['
 */
static pj_bool_t find_prev_call(pjsua_inst_id inst_id)
{
    int i, max;

    max = pjsua_call_get_max_count(inst_id);
    for (i=app_config[inst_id].current_call-1; i>=0; --i) {
        if (pjsua_call_is_active(inst_id, i)) {
            app_config[inst_id].current_call = i;
            return PJ_TRUE;
        }
    }

    for (i=max-1; i>app_config[inst_id].current_call; --i) {
        if (pjsua_call_is_active(inst_id, i)) {
            app_config[inst_id].current_call = i;
            return PJ_TRUE;
        }
    }

    app_config[inst_id].current_call = PJSUA_INVALID_ID;
    return PJ_FALSE;
}

/*
 * Print log of call states. Since call states may be too long for logger,
 * printing it is a bit tricky, it should be printed part by part as long 
 * as the logger can accept.
 */
static void log_call_dump(pjsua_inst_id inst_id, pjsua_call_id call_id) 
{
	char some_buf[1024 * 3];
    unsigned call_dump_len;
    unsigned part_len;
    unsigned part_idx;
    unsigned log_decor;
    pjsua_call_dump(inst_id, call_id, PJ_TRUE, some_buf, sizeof(some_buf), "  ");
    call_dump_len = strlen(some_buf);

    log_decor = pj_log_get_decor();
    pj_log_set_decor(log_decor & ~(PJ_LOG_HAS_NEWLINE | PJ_LOG_HAS_CR));
    PJ_LOG(3,(THIS_FILE, "\n"));
    pj_log_set_decor(0);

    part_idx = 0;
    part_len = PJ_LOG_MAX_SIZE-80;
    while (part_idx < call_dump_len) {
        char p_orig, *p;

        p = &some_buf[part_idx];
        if (part_idx + part_len > call_dump_len)
            part_len = call_dump_len - part_idx;
        p_orig = p[part_len];
        p[part_len] = '\0';
        PJ_LOG(3,(THIS_FILE, "%s", p));
        p[part_len] = p_orig;
        part_idx += part_len;
    }
    pj_log_set_decor(log_decor);
}


static pj_status_t create_ipv6_media_transports(pjsua_inst_id inst_id)
{
    pjsua_media_transport tp[PJSUA_MAX_CALLS];
    pj_status_t status;
    int port = app_config[inst_id].rtp_cfg.port;
    unsigned i;

    for (i=0; i<app_config[inst_id].cfg.max_calls; ++i) {
        enum { MAX_RETRY = 10 };
        pj_sock_t sock[2];
        pjmedia_sock_info si;
        unsigned j;

        /* Get rid of uninitialized var compiler warning with MSVC */
        status = PJ_SUCCESS;

        for (j=0; j<MAX_RETRY; ++j) {
            unsigned k;

            for (k=0; k<2; ++k) {
                pj_sockaddr bound_addr;

                status = pj_sock_socket(pj_AF_INET6(), pj_SOCK_DGRAM(), 0, &sock[k]);
                if (status != PJ_SUCCESS)
                    break;

                status = pj_sockaddr_init(pj_AF_INET6(), &bound_addr,
                                          &app_config[inst_id].rtp_cfg.bound_addr, 
                                          (unsigned short)(port+k));
                if (status != PJ_SUCCESS)
                    break;

                status = pj_sock_bind(sock[k], &bound_addr, 
                                      pj_sockaddr_get_len(&bound_addr));
                if (status != PJ_SUCCESS)
                    break;
            }
            if (status != PJ_SUCCESS) {
                if (k==1)
                    pj_sock_close(sock[0]);

                if (port != 0)
                    port += 10;
                else
                    break;

                continue;
            }

            pj_bzero(&si, sizeof(si));
            si.rtp_sock = sock[0];
            si.rtcp_sock = sock[1];
        
            pj_sockaddr_init(pj_AF_INET6(), &si.rtp_addr_name, 
                             &app_config[inst_id].rtp_cfg.public_addr, 
                             (unsigned short)(port));
            pj_sockaddr_init(pj_AF_INET6(), &si.rtcp_addr_name, 
                             &app_config[inst_id].rtp_cfg.public_addr, 
                             (unsigned short)(port+1));

            status = pjmedia_transport_udp_attach(pjsua_get_pjmedia_endpt(inst_id),
                                                  NULL,
                                                  &si,
                                                  0,
                                                  &tp[i].transport);
            if (port != 0)
                port += 10;
            else
                break;

            if (status == PJ_SUCCESS)
                break;
        }

        if (status != PJ_SUCCESS) {
            pjsua_perror(THIS_FILE, "Error creating IPv6 UDP media transport", 
                         status);
            for (j=0; j<i; ++j) {
                pjmedia_transport_close(tp[j].transport);
            }
            return status;
        }
    }

    return pjsua_media_transports_attach(inst_id, tp, i, PJ_TRUE);
}

static pj_status_t create_ipv6_media_transports2(pjsua_inst_id inst_id, pjsua_call_id call_id)
{
	pjsua_media_transport tp[PJSUA_MAX_CALLS];
	pj_status_t status;
	int port = app_config[inst_id].rtp_cfg.port;
	//unsigned i;

	//for (i=0; i<app_config.cfg.max_calls; ++i) {
		enum { MAX_RETRY = 10 };
		pj_sock_t sock[2];
		pjmedia_sock_info si;
		unsigned j;

		/* Get rid of uninitialized var compiler warning with MSVC */
		status = PJ_SUCCESS;

		for (j=0; j<MAX_RETRY; ++j) {
			unsigned k;

			for (k=0; k<2; ++k) {
				pj_sockaddr bound_addr;

				status = pj_sock_socket(pj_AF_INET6(), pj_SOCK_DGRAM(), 0, &sock[k]);
				if (status != PJ_SUCCESS)
					break;

				status = pj_sockaddr_init(pj_AF_INET6(), &bound_addr,
					&app_config[inst_id].rtp_cfg.bound_addr, 
					(unsigned short)(port+k));
				if (status != PJ_SUCCESS)
					break;

				status = pj_sock_bind(sock[k], &bound_addr, 
					pj_sockaddr_get_len(&bound_addr));
				if (status != PJ_SUCCESS)
					break;
			}
			if (status != PJ_SUCCESS) {
				if (k==1)
					pj_sock_close(sock[0]);

				if (port != 0)
					port += 10;
				else
					break;

				continue;
			}

			pj_bzero(&si, sizeof(si));
			si.rtp_sock = sock[0];
			si.rtcp_sock = sock[1];

			pj_sockaddr_init(pj_AF_INET6(), &si.rtp_addr_name, 
				&app_config[inst_id].rtp_cfg.public_addr, 
				(unsigned short)(port));
			pj_sockaddr_init(pj_AF_INET6(), &si.rtcp_addr_name, 
				&app_config[inst_id].rtp_cfg.public_addr, 
				(unsigned short)(port+1));

			status = pjmedia_transport_udp_attach(pjsua_get_pjmedia_endpt(inst_id),
				NULL,
				&si,
				0,
				&tp[call_id].transport);
			if (port != 0)
				port += 10;
			else
				break;

			if (status == PJ_SUCCESS)
				break;
		}

		if (status != PJ_SUCCESS) {
			pjsua_perror(THIS_FILE, "Error creating IPv6 UDP media transport", 
				status);
			for (j=0; j<call_id; ++j) {
				pjmedia_transport_close(tp[j].transport);
			}
			return status;
		}
	//}

	return pjsua_media_transports_attach(inst_id, tp, call_id, PJ_TRUE);
}

/*
 * Read command arguments from config file.
 */
int my_read_natnl_config_file(const char *filename, 
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
	//printf("Unable to open config file %s", filename);
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
	//printf("Too many arguments specified in cmd line/config file");
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
int my_parse_natnl_config(int argc, char *argv[],
					struct natnl_config *cfg)
{
    int c;
    int option_index;
	enum natnl_file_access {
		NATNL_O_RDONLY     = 0x1101,   /**< Open file for reading.             */
		NATNL_O_WRONLY     = 0x1102,   /**< Open file for writing.             */
		NATNL_O_RDWR       = 0x1103,   /**< Open file for reading and writing. 
										 File will be truncated.            */
		NATNL_O_APPEND     = 0x1108,    /**< Append to existing file.           */
		NATNL_O_SYSLOG     = 0x1110     /**< Write to sys log.           */
	};
    enum { OPT_LOG_CONFIG_FILE=127, OPT_LOG_FILE, OPT_LOG_LEVEL, OPT_APP_LOG_LEVEL, 

	   OPT_LOG_APPEND, OPT_LOG_SYSLOG, OPT_SYSLOG_FACILITY, OPT_LOG_FILE_SIZE,
	   
	   OPT_LOG_ROTATE_NUMBER, OPT_LOG_FLAG_FILE, OPT_DISABLE_CONSOLE_LOG, 
	   
	   OPT_DISABLE_SDP_COMPRESS

    };
//	struct pj_getopt_option long_options[32];
	struct pj_getopt_option long_options[] = {	
	{ "log-config-file",1, 0, OPT_LOG_CONFIG_FILE},
	{ "log-file",	1, 0, OPT_LOG_FILE},
	{ "log-level",	1, 0, OPT_LOG_LEVEL},
	{ "app-log-level",1,0,OPT_APP_LOG_LEVEL},
	{ "log-append", 1, 0, OPT_LOG_APPEND}, 
	{ "log-to-syslog",	0, 0, OPT_LOG_SYSLOG},
	{ "syslog-facility",1, 0, OPT_SYSLOG_FACILITY},
	{ "log-file-size",1, 0, OPT_LOG_FILE_SIZE},
	{ "log-rotate-number",	1, 0, OPT_LOG_ROTATE_NUMBER},
	{ "log-flag-file",	1, 0, OPT_LOG_FLAG_FILE},
	{ "disable-console-log",	0, 0, OPT_DISABLE_CONSOLE_LOG},
	{ "disable-sdp-compress", 1, 0, OPT_DISABLE_SDP_COMPRESS}, 

	{ NULL, 0, 0, 0}
    };
    int status;
    char *config_file = NULL;

    /* Run pj_getopt once to see if user specifies config file to read. */ 
    pj_optind = 0;
    while ((c=pj_getopt_long(argc, argv, "", long_options, 
			     &option_index)) != -1) 
    {
	switch (c) {
	case OPT_LOG_CONFIG_FILE:
	    config_file = pj_optarg;
	    break;
	}
	if (config_file)
	    break;
    }

    if (config_file) {
	status = my_read_natnl_config_file(config_file, &argc, &argv);
	if (status != 0)
	    return status;
    }

    //cfg->acc_cnt = 0;
    //cur_acc = &cfg->acc_cfg[0];

    // assign default value first
	cfg->log_cfg.log_level = 4;
	memset(cfg->log_cfg.log_filename, 0, 
		sizeof(cfg->log_cfg.log_filename));
	cfg->log_cfg.log_file_flags = 0;
	cfg->log_cfg.log_file_size = 0;
	cfg->log_cfg.log_rotate_number = 0;
	memset(cfg->log_cfg.log_flag_file, 0, 
		sizeof(cfg->log_cfg.log_flag_file));
	cfg->log_cfg.disable_console_log = 0;
#if 0
	strcpy(natnl_cfg->turn_usr, TURN_USR);
    strcpy(natnl_cfg->turn_pwd, TURN_PWD);
#endif

    /* Reinitialize and re-run pj_getopt again, possibly with new arguments
     * read from config file.
     */
    pj_optind = 0;
	while((c=pj_getopt_long(argc,argv, "", long_options,&option_index))!=-1) {

		switch (c) {

		case OPT_LOG_CONFIG_FILE:
			/* Ignore as this has been processed before */
			break;

		case OPT_LOG_LEVEL:
			c = strtoul(pj_optarg, NULL, 0);
			if (c < 0 || c > 6) {
				//printf("[main.c] Error: expecting log-level integer value 0~6\n");
				return -2;
			}
			cfg->log_cfg.log_level = c;
			//printf("[main.c] pars_args natnl_cfg->log_level=%d\n", cfg->log_cfg.log_level);
			break;

		case OPT_LOG_FILE:
			if (strlen(pj_optarg) > sizeof(cfg->log_cfg.log_filename)) {
				//printf("[main.c] Error: log-filename is too long. limits is %d\n",
				//	sizeof(cfg->log_cfg.log_filename));
				return -2;
			}
			strncpy(cfg->log_cfg.log_filename, pj_optarg, strlen(pj_optarg));
			break;

		case OPT_LOG_APPEND:
			cfg->log_cfg.log_file_flags |= NATNL_O_APPEND;
			break;

		case OPT_LOG_SYSLOG:
			cfg->log_cfg.log_file_flags |= NATNL_O_SYSLOG;
			//printf("[main.c] pars_args natnl_cfg->log_file_flags=%d\n", cfg->log_cfg.log_file_flags);
			break;

		case OPT_SYSLOG_FACILITY:
			c = strtoul(pj_optarg, NULL, 0);
			cfg->log_cfg.syslog_facility = c;
			//printf("[main.c] pars_args natnl_cfg->syslog_facility=%d\n", cfg->log_cfg.syslog_facility);
			break;

		case OPT_LOG_FILE_SIZE:
			c = strtoul(pj_optarg, NULL, 0);
			cfg->log_cfg.log_file_size = c;
			//printf("[main.c] pars_args natnl_cfg->log_file_size=%d\n", cfg->log_cfg.log_file_size);
			break;

		case OPT_LOG_ROTATE_NUMBER:
			c = strtoul(pj_optarg, NULL, 0);
			cfg->log_cfg.log_rotate_number = c;
			//printf("[main.c] pars_args natnl_cfg->log_rotate_number=%d\n", cfg->log_cfg.log_rotate_number);
			break;

		case OPT_LOG_FLAG_FILE:
			if (strlen(pj_optarg) > sizeof(cfg->log_cfg.log_flag_file)) {
				//printf("[main.c] Error: log-flag-file is too long. limits is %d\n",
				//	sizeof(cfg->log_cfg.log_flag_file));
				return -2;
			}
			strncpy(cfg->log_cfg.log_flag_file, pj_optarg, strlen(pj_optarg));
			break;

		case OPT_DISABLE_CONSOLE_LOG:
			cfg->log_cfg.disable_console_log = 1;
			//printf("[main.c] pars_args natnl_cfg->disable_console_log=%d\n", cfg->log_cfg.disable_console_log);
			break;

		case OPT_DISABLE_SDP_COMPRESS:
			cfg->disable_sdp_compress = 1;
			//printf("[main.c] pars_args natnl_cfg->disable_sdp_compress=true\n");
			break;

		default:
			//printf("Argument \"%s\" is not valid. Use --help to see help\n",
			//	  argv[pj_optind-1]);
			return -1;
		}
    }

	free(argv);

    return 0;
}

/* Set default config. */
static void default_app_config(pjsua_inst_id inst_id, struct app_config *cfg)
{
    char tmp[80];
    unsigned i;

    pjsua_config_default(&cfg->cfg);
	pj_memset(tmp, 0, sizeof(tmp));
    pj_ansi_sprintf(tmp, "ASUSNATNL v%s %s", natnl_get_version(), pj_get_sys_info()->info.ptr);
    //pj_strdup2_with_null(pjsip_get_app_pool(inst_id), &cfg->cfg.user_agent, tmp);

	cfg->cfg.user_agent.slen = pj_ansi_strlen(tmp);
	if (cfg->cfg.user_agent.slen) {
		cfg->cfg.user_agent.ptr = (char*)malloc(cfg->cfg.user_agent.slen+1);
		pj_memcpy(cfg->cfg.user_agent.ptr, tmp, cfg->cfg.user_agent.slen);
	}
	cfg->cfg.user_agent.ptr[cfg->cfg.user_agent.slen] = '\0';

    pjsua_logging_config_default(&cfg->log_cfg);
    pjsua_media_config_default(&cfg->media_cfg);
    pjsua_transport_config_default(&cfg->udp_cfg);
    //DEAN
    //cfg->udp_cfg.port = 5060;
    pjsua_transport_config_default(&cfg->rtp_cfg);
	cfg->current_call = PJSUA_INVALID_ID;
    if (stricmp(app_config[inst_id].natnl_cfg.device_id, UA1) == 0) {
        //cfg->udp_cfg.port = 5060;
        cfg->rtp_cfg.port = 0;
    } else {
        //cfg->udp_cfg.port = 5070;
        cfg->rtp_cfg.port = 0;
    }
    cfg->redir_op = PJSIP_REDIRECT_ACCEPT;

    for (i=0; i<PJ_ARRAY_SIZE(cfg->acc_cfg); ++i)
		pjsua_acc_config_default(inst_id, &cfg->acc_cfg[i]);

    //for (i=0; i<PJ_ARRAY_SIZE(cfg->buddy_cfg); ++i)
	//	pjsua_buddy_config_default(&cfg->buddy_cfg[i]);

	//log level

	{
		// check if dumplog file exists, if true then set log parameter
		char curr[260];
#ifdef WIN32
		GetCurrentDirectoryA(260, curr);
		DBG("!!!!!%s", curr);
		FILE *pFile = fopen("c:\\natnl_log.cfg", "r");
		if (pFile)
			DBG("!!!!!natnl_log.cfg exists.");
		else
			DBG("!!!!!natnl_log.cfg does not exist.");
		char *arg[2] = {"", "--log-config-file=c:\\natnl_log.cfg"};
#else
		FILE *pFile = fopen("natnl_log.cfg", "r");
		char *arg[2] = {"", "--log-config-file=natnl_log.cfg"};
#endif
		if (pFile) {
			fclose(pFile);
			my_parse_natnl_config(2, arg, &app_config[inst_id].natnl_cfg);
		}

		cfg->log_cfg.level = app_config[inst_id].natnl_cfg.log_cfg.log_level; // DEAN modified
		cfg->log_cfg.console_level = app_config[inst_id].natnl_cfg.log_cfg.log_level;
		cfg->log_cfg.log_file_flags = app_config[inst_id].natnl_cfg.log_cfg.log_file_flags;
		cfg->log_cfg.log_file_size = app_config[inst_id].natnl_cfg.log_cfg.log_file_size;
		cfg->log_cfg.log_rotate_number = app_config[inst_id].natnl_cfg.log_cfg.log_rotate_number;
		if (strlen(app_config[inst_id].natnl_cfg.log_cfg.log_filename) > 0)
			cfg->log_cfg.log_filename = pj_str(app_config[inst_id].natnl_cfg.log_cfg.log_filename);
		if (strlen(app_config[inst_id].natnl_cfg.log_cfg.log_flag_file) > 0)
			cfg->log_cfg.log_flag_file = pj_str(app_config[inst_id].natnl_cfg.log_cfg.log_flag_file);
		cfg->log_cfg.facility = app_config[inst_id].natnl_cfg.log_cfg.syslog_facility;
		cfg->log_cfg.disable_console_log = app_config[inst_id].natnl_cfg.log_cfg.disable_console_log; // DEAN modified
	}
}

/* Get configuration from config file */
static void config_app_config(pjsua_inst_id inst_id, struct app_config *cfg)
{
	int i;
	pjsua_acc_config *cur_acc;

	//cfg->cfg.outbound_proxy[cfg->cfg.outbound_proxy_cnt++] = pj_str("sip:aae-sgsip065-2.asus.com:5061");
	pjsua_var[inst_id].ua_cfg.force_lr = 0;

	for(i=0;i<ACCOUNT_CNT;i++) {
		cur_acc = &cfg->acc_cfg[i];

		char tmp_device_id[128];

		strcpy(tmp_device_id, app_config[inst_id].natnl_cfg.device_id);

		PJ_LOG(4, (THIS_FILE, "device_id=%s", tmp_device_id));

		char *tmp;
		tmp = strtok(tmp_device_id, "@");
		if (tmp)
			strcpy(app_config[inst_id].username, tmp);
		tmp = strtok(NULL, "@");
		if (tmp)
			strcpy(app_config[inst_id].realm, tmp);

		sprintf(app_config[inst_id].account_id, "sip:%s", app_config[inst_id].natnl_cfg.device_id);

    	//SIP account
		cur_acc->id = pj_str(app_config[inst_id].account_id);
    
    	//Registrar
		cur_acc->reg_uri = pj_str(app_config[inst_id].registrar_uri_str);
    	//cur_acc->reg_uri = pj_str("sip:192.168.123.251;transport=tcp");
    
    	//Realm
    	cur_acc->cred_info[cur_acc->cred_count].realm = pj_str(app_config[inst_id].realm);
    
    	//authentication Username
        cur_acc->cred_info[cur_acc->cred_count].username = pj_str(app_config[inst_id].username);
        cur_acc->cred_info[cur_acc->cred_count].scheme = pj_str("Digest");
    
    	//authentication Password
        cur_acc->cred_info[cur_acc->cred_count].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
        cur_acc->cred_info[cur_acc->cred_count].data = pj_str(app_config[inst_id].natnl_cfg.device_pwd);
        cur_acc->cred_count++;  //DEAN fix bug. Cannot get authorization with sip server.
    
    	//Registrar Expire Timer
    	cur_acc->reg_timeout = 3600;
    
    	//Enable account Session Timer
		cur_acc->use_timer = PJSUA_SIP_TIMER_OPTIONAL;

		// DEAN. Check fast init or not. If fast _init is true, don't register 
		if (app_config[inst_id].natnl_cfg.fast_init)
			cur_acc->register_on_acc_add = PJ_FALSE;

		app_config[inst_id].acc_cnt++;
	}

	//Enable global Session Timer
    cfg->cfg.use_timer = PJSUA_SIP_TIMER_OPTIONAL;

	//STUN server
	for (i = 0; i < app_config[inst_id].natnl_cfg.stun_srv_cnt; i++)
	{
		if (i == 0)
			cfg->cfg.stun_host = pj_str(app_config[inst_id].natnl_cfg.stun_srv[i]);
		
		cfg->cfg.stun_srv[cfg->cfg.stun_srv_cnt++] = pj_str(app_config[inst_id].natnl_cfg.stun_srv[i]);
	}
	
	cfg->cfg.stun_ignore_failure = PJ_FALSE;

	//Enable ICE
    #if ENABLE_ICE
	cfg->media_cfg.enable_ice = PJ_TRUE;
    #else
    cfg->media_cfg.enable_ice = PJ_FALSE;
    #endif

	cfg->media_cfg.disable_sdp_compress = app_config[inst_id].natnl_cfg.disable_sdp_compress;

    /**
     * always enable ICE -- Andrew (2013/01/23)
     */
	cfg->media_cfg.enable_ice = PJ_TRUE;

    if (cfg->media_cfg.enable_ice && 
        app_config[inst_id].natnl_cfg.use_turn && 
		app_config[inst_id].natnl_cfg.turn_srv_cnt)
		cfg->media_cfg.enable_turn = PJ_TRUE;

    if (cfg->media_cfg.enable_turn) {
		cfg->media_cfg.turn_server_cnt = app_config[inst_id].natnl_cfg.turn_srv_cnt;
		
		for (i = 0; i < app_config[inst_id].natnl_cfg.turn_srv_cnt; i++) {
			if (i == 0)
				cfg->media_cfg.turn_server = pj_str(app_config[inst_id].natnl_cfg.turn_srv[i]);

			cfg->media_cfg.turn_server_list[i] = pj_str(app_config[inst_id].natnl_cfg.turn_srv[i]);
		}
        
		cfg->media_cfg.turn_conn_type = PJ_TURN_TP_UDP;
        cfg->media_cfg.turn_auth_cred.type = PJ_STUN_AUTH_CRED_STATIC;
        cfg->media_cfg.turn_auth_cred.data.static_cred.realm = pj_str(app_config[inst_id].realm);
        cfg->media_cfg.turn_auth_cred.data.static_cred.username = pj_str(app_config[inst_id].username);

        cfg->media_cfg.turn_auth_cred.data.static_cred.data = pj_str(app_config[inst_id].natnl_cfg.device_pwd);
        cfg->media_cfg.turn_auth_cred.data.static_cred.data_type = PJ_STUN_PASSWD_PLAIN;
        //cfg->media_cfg.turn_auth_cred.data.static_cred.nonce = pj_str("");
    }

	// Config media TLS config
	pj_bzero(&cfg->media_cfg.tls_cfg, sizeof(pj_ssl_sock_cfg));
	cfg->media_cfg.enable_secure_data = (app_config[inst_id].natnl_cfg.enable_secure_data > 0);
	cfg->media_cfg.tls_cfg.cert_file = pj_str(app_config[inst_id].natnl_cfg.cert);
	cfg->media_cfg.tls_cfg.privkey_file = pj_str(app_config[inst_id].natnl_cfg.cert_pkey);
	cfg->media_cfg.tls_cfg.ca_list_file = pj_str(app_config[inst_id].natnl_cfg.trusted_ca_certs);
	cfg->media_cfg.tls_cfg.verify_server = (app_config[inst_id].natnl_cfg.verify_server_peer > 0);

	//cfg->rtp_cfg.sock_recv_buf_size = 1460*1024;
	//cfg->rtp_cfg.sock_send_buf_size = 1460*64;

	// DEAN The number of maximum calls
	cfg->cfg.max_calls = app_config[inst_id].natnl_cfg.max_calls;
	// ensure max_call greater than 0
	if (!cfg->cfg.max_calls || cfg->cfg.max_calls > PJSUA_MAX_CALLS)
		cfg->cfg.max_calls = PJSUA_MAX_CALLS;

	//When incomming call, auto answer the call with 200 OK
    app_config[inst_id].auto_answer = 200;

#ifdef USE_PORTAUDIO
	cfg->capture_dev = 5;
	cfg->playback_dev = 5;
#else
	cfg->capture_dev = NULL_SND_DEV_ID;
	cfg->playback_dev = NULL_SND_DEV_ID;
#endif

	// use stun candidate or not
	cfg->use_stun_cand = app_config[inst_id].natnl_cfg.use_stun;
	cfg->use_turn_flag = app_config[inst_id].natnl_cfg.use_turn;
	cfg->use_tls = app_config[inst_id].natnl_cfg.use_tls > 0;
	
	if (strlen(app_config[inst_id].natnl_cfg.sip_trusted_ca_certs))
		cfg->udp_cfg.tls_setting.ca_list_file = pj_str(app_config[inst_id].natnl_cfg.sip_trusted_ca_certs);
	cfg->udp_cfg.tls_setting.verify_server = app_config[inst_id].natnl_cfg.sip_verify_server_peer;
}

/* Notification on incoming request */
static pj_bool_t default_mod_on_rx_request(pjsip_rx_data *rdata)
{
    PJ_LOG(4, (THIS_FILE, "[call flow] default_mod_on_rx_request()."));
    pjsip_tx_data *tdata;
    pjsip_status_code status_code;
    pj_status_t status;

	pjsua_inst_id inst_id = rdata->tp_info.pool->factory->inst_id;

    /* Don't respond to ACK! */
    if (pjsip_method_cmp(&rdata->msg_info.msg->line.req.method, &pjsip_ack_method) == 0)
        return PJ_TRUE;

    /* Create basic response. */
    if (pjsip_method_cmp(&rdata->msg_info.msg->line.req.method, &pjsip_notify_method) == 0)
    {
        /* Unsolicited NOTIFY's, send with Bad Request */
        status_code = PJSIP_SC_BAD_REQUEST;
    } else {
        /* Probably unknown method */
        status_code = PJSIP_SC_METHOD_NOT_ALLOWED;
    }
    status = pjsip_endpt_create_response(pjsua_get_pjsip_endpt(inst_id), rdata, status_code, NULL, &tdata);
    if (status != PJ_SUCCESS) {
        pjsua_perror(THIS_FILE, "Unable to create response", status);
        return PJ_TRUE;
    }

    /* Add Allow if we're responding with 405 */
    if (status_code == PJSIP_SC_METHOD_NOT_ALLOWED) {
        const pjsip_hdr *cap_hdr;
        cap_hdr = pjsip_endpt_get_capability(pjsua_get_pjsip_endpt(inst_id), PJSIP_H_ALLOW, NULL);
        if (cap_hdr) {
            pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)pjsip_hdr_clone(tdata->pool, cap_hdr));
        }
    }

    /* Add User-Agent header */
    {
        pj_str_t user_agent;
        char tmp[80];
        const pj_str_t USER_AGENT = { "User-Agent", 10};
        pjsip_hdr *h;

        pj_ansi_snprintf(tmp, sizeof(tmp), "PJSUA v%s/%s", pj_get_version(), PJ_OS_NAME);
        pj_strdup2_with_null(tdata->pool, &user_agent, tmp);

        h = (pjsip_hdr*) pjsip_generic_string_hdr_create(tdata->pool, &USER_AGENT, &user_agent);
        pjsip_msg_add_hdr(tdata->msg, h);
    }

    pjsip_endpt_send_response2(pjsua_get_pjsip_endpt(inst_id), rdata, tdata, NULL, NULL);

    return PJ_TRUE;
}


/* The module instance. */
static pjsip_module mod_default_handler_initializer = 
{
    NULL, NULL,				/* prev, next.		*/
    { "mod-default-handler", 19 },	/* Name.		*/
    -1,					/* Id			*/
    PJSIP_MOD_PRIORITY_APPLICATION+99,	/* Priority	        */
    NULL,				/* load()		*/
    NULL,				/* start()		*/
    NULL,				/* stop()		*/
    NULL,				/* unload()		*/
    &default_mod_on_rx_request,		/* on_rx_request()	*/
    NULL,				/* on_rx_response()	*/
    NULL,				/* on_tx_request.	*/
    NULL,				/* on_tx_response()	*/
    NULL,				/* on_tsx_state()	*/

};

static pjsip_module mod_default_handler[PJSUA_MAX_INSTANCES];
static int is_initialized;

static void mod_default_handler_initialize()
{
	int i;
	if(is_initialized)
		return;

	for (i=0; i < PJ_ARRAY_SIZE(mod_default_handler); i++)
	{
		mod_default_handler[i] = mod_default_handler_initializer;
	}

	is_initialized = 1;
}

/* 
 * DEAN modified 
 * NAT type detection callback.
 */
static void on_nat_detect(pjsua_inst_id inst_id,
						  void *local_addr, void* mapped_addr, 
                          const pj_stun_nat_detect_result *res)
{
	pj_sockaddr_in *local_sockaddr_in = (pj_sockaddr_in *)local_addr;
	pj_sockaddr_in *mapped_sockaddr_in = (pj_sockaddr_in *)mapped_addr;

	pj_memcpy(&pjsua_var[inst_id].stun_local_addr, local_sockaddr_in, sizeof(pj_sockaddr_in));
	pj_memcpy(&pjsua_var[inst_id].stun_mapped_addr, mapped_sockaddr_in, sizeof(pj_sockaddr_in));
	PJ_LOG(4, (THIS_FILE, "on_nat_detect() local_addr andmapped_addr saved. family=%d, port=%d", 
		mapped_sockaddr_in->sin_family, mapped_sockaddr_in->sin_port));
	// if status is -1, it is TEST_1 response received.
	if (res->status == -1)
		return;

	// save stun mapped address and nat_type
	pj_memcpy(&app_config[inst_id].stun_local_addr, &pjsua_var[inst_id].stun_local_addr, sizeof(pj_sockaddr_in));
	pj_memcpy(&app_config[inst_id].stun_mapped_addr, &pjsua_var[inst_id].stun_mapped_addr, sizeof(pj_sockaddr_in));
	app_config[inst_id].nat_type = res->nat_type;
	app_config[inst_id].nat_type_detected = PJ_TRUE;
	pj_memset(app_config[inst_id].nat_type_name, 0, sizeof(app_config[inst_id].nat_type_name));
	pj_memcpy(app_config[inst_id].nat_type_name, res->nat_type_name, strlen(res->nat_type_name));

    PJ_LOG(4, (THIS_FILE, "[call flow] on_nat_detect()."));

    if (res->status != PJ_SUCCESS) {
        pjsua_perror(THIS_FILE, "NAT detection failed", res->status);
    } else {
        PJ_LOG(3, (THIS_FILE, "NAT detected as %s", res->nat_type_name));
	}

	// check setting for using upnp or not.
	if (app_config[inst_id].natnl_cfg.upnp_cfg.flag == 0) {
		//goto CALL_CALLBACK;
		return;
	}

	app_config[inst_id].use_upnp_flag = app_config[inst_id].natnl_cfg.upnp_cfg.flag;

	// if nat type is open, use tcp but no need to check upnp.
	if (app_config[inst_id].nat_type == PJ_STUN_NAT_TYPE_OPEN) {
		PJ_LOG(4, (THIS_FILE, "NAT Type is open. Use TCP (without upnp).\n"));
		//goto CALL_CALLBACK;
		return;
	}

	// if upnp_flag is 1, use tcp but no need to check upnp.
	if (app_config[inst_id].natnl_cfg.upnp_cfg.flag == 1) {
		PJ_LOG(4, (THIS_FILE, "UPnP flag is 1. Use TCP(with upnp).\n"));
	}

	// if upnp_flag is 2, use tcp but no need to check upnp.
	if (app_config[inst_id].natnl_cfg.upnp_cfg.flag == 2) {
		PJ_LOG(4, (THIS_FILE, "UPnP flag is 2. Use TCP(without upnp).\n"));
		//goto CALL_CALLBACK;
		return;
	}
}

static pj_status_t on_stun_binding_complete(pjsua_inst_id inst_id, 
									 int idx,
									 pj_sockaddr *local_addr, 
									 int ip_chagned_type) {
	pj_timestamp now;
	pj_uint32_t elapsed_time;
	int retry_cnt = 0;

	PJ_UNUSED_ARG(idx);
	PJ_UNUSED_ARG(local_addr);

	// 2013-10-22 DEAN. Move from on_natnl_detect(). This guaranty upnp tcp candidate to be added.
	app_config[inst_id].use_upnp_flag = app_config[inst_id].natnl_cfg.upnp_cfg.flag;  

	// check the time of the latest ip changed.
	// if it was 2 seconds ago, we should init upnp again.
	if (ip_chagned_type > 0) {
		pj_get_timestamp(&now);
		elapsed_time = pj_elapsed_msec(&app_config[inst_id].last_ip_changed, &now);
		if ((elapsed_time/1000) > 2) {
			PJ_LOG(4, (THIS_FILE, "on_stun_binding_complete(), "
				"IP changed detected, detect nat type and init upnp again. elapsed_time=%d ms", elapsed_time));
			
			if (!app_config[inst_id].natnl_cfg.fast_init)
			{
				// refresh nat type
				//pjsua_detect_nat_type(inst_id);
				
				// refresh upnp inited
#ifdef COLLECT_TCP_CAND
				int ret = InitUpnp(&app_config[inst_id].upnp);
				if (ret != 0)
					return -1;
#endif
			}


			// Set current time to last_ip_changed time.
			pj_get_timestamp(&app_config[inst_id].last_ip_changed);
		}
	}
	return PJ_SUCCESS;
}

#if 0
static pj_status_t on_tcp_server_binding_complete(pjsua_inst_id inst_id, int idx,
										 pj_sockaddr *external_addr,
										 pj_sockaddr *local_addr) {
	 char local_str_addr_with_port[PJ_INET6_ADDRSTRLEN+10];
	 char external_str_addr_with_port[PJ_INET6_ADDRSTRLEN+10];
	 char local_str_addr[PJ_INET6_ADDRSTRLEN+10];
	 char external_str_addr[PJ_INET6_ADDRSTRLEN+10];
#if 0
	 pj_timestamp now;
	 pj_uint32_t elapsed_time;
#endif
	 pj_uint16_t eport ,lport;
	 int retry_cnt = 0;
	 pj_str_t upnp_external_addr;

	 pj_sockaddr_print(local_addr, local_str_addr_with_port, sizeof(local_str_addr_with_port), 3);
	 pj_sockaddr_print(external_addr, external_str_addr_with_port, sizeof(external_str_addr_with_port), 3);

	 pj_sockaddr_print(local_addr, local_str_addr, sizeof(local_str_addr), 0);
	 pj_sockaddr_print(external_addr, external_str_addr, sizeof(external_str_addr), 0);

	 app_config[inst_id].upnp_port[idx] = 0;

	 // 2013-10-22 DEAN. Move from on_natnl_detect(). This guaranty upnp tcp candidate to be added.
	 app_config[inst_id].use_upnp_flag = app_config[inst_id].natnl_cfg.upnp_cfg.flag;  

	 // DEAN. Independent from stun binding, so we can't check ip changed.
	 // Just do this check in on_stun_binding_complete.
#if 0  
	 // check the time of the latest ip changed.
	 // if it was 2 seconds ago, we should init upnp again.
	 if (ip_chagned_type > 0) {
		 pj_get_timestamp(&now);
		 elapsed_time = pj_elapsed_msec(&app_config[inst_id].last_ip_changed, &now);
		 if ((elapsed_time/1000) > 2) {
			 PJ_LOG(4, (THIS_FILE, "on_stun_binding_complete(), "
				 "IP changed detected, detect nat type and init upnp again. elapsed_time=%d ms", elapsed_time));

			 if (!app_config[inst_id].natnl_cfg.fast_init)
			 {
				 // refresh nat type
				 //pjsua_detect_nat_type(inst_id);

				 // refresh upnp inited
				 int ret = InitUpnp(&app_config[inst_id].upnp);
				 if (ret != 0)
					 return -1;
			 }


			 // Set current time to last_ip_changed time.
			 pj_get_timestamp(&app_config[inst_id].last_ip_changed);
		 }
	 }
#endif

	 eport = lport = pj_sockaddr_get_port(local_addr);
	 pj_sockaddr_set_port(external_addr, eport); // update external port

	 upnp_external_addr = pj_str(app_config[inst_id].upnp.extaddr);
	 if (app_config[inst_id].upnp.inited && 
		 !is_private_ip(&upnp_external_addr)) {
			 char seport[6], slport[6];
			 char intClient[PJ_INET6_ADDRSTRLEN+10];
			 char intPort[6];
			 int r = 0;
			 if (lport > 0) {
RE_CHECK_EPORT:
				 if (retry_cnt >= 3)
				 {
					 PJ_LOG(4, (THIS_FILE, "on_tcp_server_binding_complete() SetRedirectAndTest retry count >= 3. Give up."));
					 return -2;
				 }
				 sprintf(seport, "%d", eport);
				 sprintf(slport, "%d", lport);
				
				 r = UPNP_GetSpecificPortMappingEntry(app_config[inst_id].upnp.upnpurls.controlURL,
													 app_config[inst_id].upnp.igddata.first.servicetype,
													 seport, "TCP", intClient,
													 intPort, NULL, NULL, NULL);

				 if(r == UPNPCOMMAND_SUCCESS) {
					 pj_time_val now, expire;
					 pj_gettimeofday(&now);
					 pj_srand((unsigned)now.msec);
					 pj_init_random_seed();
					 // random a external port number between 49152~65535
					 eport = pj_rand() % 16384 + 49152;
					 retry_cnt++;
					 PJ_LOG(4, (__FILE__, "UPNP_GetSpecificPortMappingEntry() success. eport=[%s] is already used by [%s:%s]. Try next random eport=[%d]",
						 seport, intClient, intPort, eport));
					 goto RE_CHECK_EPORT;
				 }

				 r = UPNP_AddPortMapping(app_config[inst_id].upnp.upnpurls.controlURL,
										app_config[inst_id].upnp.igddata.first.servicetype,
										 seport, slport, local_str_addr, 
										 ASUS_UPNP_DESC, "TCP", 0, "86400");

				 if (r == 0)
				 {					
					 if (pj_sockaddr_parse(PJ_AF_UNSPEC, 0, &upnp_external_addr, external_addr) != PJ_SUCCESS) {
						 PJ_LOG(4, (THIS_FILE, "on_tcp_server_binding_complete() upnp external address [%s]", 
							 upnp_external_addr));
						 return -4;
					 }
					 pj_sockaddr_set_port(external_addr, eport);
					 PJ_LOG(4, (THIS_FILE, "on_tcp_server_binding_complete() upnp port mapping=[%d] tcp [%s] <-> [%s:%d]", 
						 r, local_str_addr_with_port, app_config[inst_id].upnp.extaddr, eport));

					 app_config[inst_id].upnp_port_mapping_cnt++;
					 app_config[inst_id].upnp_port[idx] = eport;
					 pjsua_var[inst_id].calls[idx].tcp_external_port = eport;
					 return PJ_SUCCESS;
				 }
				 else
				 {
					 PJ_LOG(1, (__FILE__, "on_tcp_server_binding_complete(). Failed to set upnp port mapping=[%d] tcp [%s] <-> [%s:%d].", 
						 r, local_str_addr_with_port, app_config[inst_id].upnp.extaddr, eport));

					 return -5;
				 }
			 }
	 }
	 return -3;
}
#endif

static void on_pager2(pjsua_inst_id inst_id,
					  pjsua_call_id call_id, const pj_str_t *from,
					  const pj_str_t *to, const pj_str_t *contact,
					  const pj_str_t *mime_type, const pj_str_t *body,
					  pjsip_rx_data *rdata, pjsua_acc_id acc_id) {

	pj_thread_t *thread;
	struct natnl_im_data *im_data;
	const pj_str_t RPORT_STR_HDR = {"Rport", 5};
	pjsip_generic_string_hdr* rport = (pjsip_generic_string_hdr *)pjsip_msg_find_hdr_by_name(
											rdata->msg_info.msg, &RPORT_STR_HDR, NULL);
	const pj_str_t TIMEOUT_STR_HDR = {"Timeout", 7};
	pjsip_generic_string_hdr* timeout = (pjsip_generic_string_hdr *)pjsip_msg_find_hdr_by_name(
											rdata->msg_info.msg, &TIMEOUT_STR_HDR, NULL);
	const pj_str_t PROC_NAME_STR_HDR = {"Pname", 5};
	pjsip_generic_string_hdr* proc_name = (pjsip_generic_string_hdr *)pjsip_msg_find_hdr_by_name(
											rdata->msg_info.msg, &PROC_NAME_STR_HDR, NULL);

	PJ_LOG(4, (THIS_FILE, "on_pager2() got incoming instant message. msg=%.*s", body->slen, body->ptr));

	im_data = (struct natnl_im_data *)malloc(sizeof(struct natnl_im_data));
	im_data->inst_id = inst_id;
	im_data->rport = 0;
	im_data->proc_name = NULL;
	if (rport) {
		im_data->rport = atoi(rport->hvalue.ptr);
	PJ_LOG(4, (THIS_FILE, "on_pager2() got incoming instant message. rport=%.*s", rport->hvalue.slen, rport->hvalue.ptr));
	}
	if (proc_name && proc_name->hvalue.slen) {
		im_data->proc_name = (char *)malloc(proc_name->hvalue.slen+1);
		memset(im_data->proc_name, 0, proc_name->hvalue.slen+1);
		memcpy(im_data->proc_name, proc_name->hvalue.ptr, proc_name->hvalue.slen);
	PJ_LOG(4, (THIS_FILE, "on_pager2() got incoming instant message. proc_name=%.*s", proc_name->hvalue.slen, proc_name->hvalue.ptr));
	}
	im_data->body = (pj_str_t *)body;
	im_data->rdata = rdata;
	/*if (rdata->msg_info.msg->body->len) {
		im_data->r_msg = (pj_str_t *)malloc(sizeof(pj_str_t));
		im_data->r_msg->ptr = (char *)malloc(rdata->msg_info.msg->body->len);
		memcpy(im_data->r_msg->ptr, rdata->msg_info.msg->body->data, rdata->msg_info.msg->body->len);
		im_data->r_msg->slen = rdata->msg_info.msg->body->len;
	} else {
		im_data->r_msg = NULL;
	}*/
	im_data->r_msg = NULL;
	im_data->timeout_sec = atoi(timeout->hvalue.ptr);
	//pj_thread_create(pjsip_get_app_pool(inst_id), "natnl_im", &im_handler_thread, im_data, 0, 0, &thread);

	// Dispatch message 
	if (im_data->rport)
		im_handler_thread(im_data);
#if !defined(WIN32) && !defined(PJ_ANDROID)
	else if (im_data->proc_name)
		send_im_by_sig(im_data);
#endif
}

static void on_pager_status2(pjsua_inst_id inst_id,
						 pjsua_call_id call_id,
						 const pj_str_t *to,
						 const pj_str_t *body,
						 void *user_data,
						 pjsip_status_code status,
						 const pj_str_t *reason,
						 pjsip_tx_data *tdata,
						 pjsip_rx_data *rdata,
						 pjsua_acc_id acc_id) {
	struct natnl_data *data = (struct natnl_data *)user_data;
	pj_str_t *resp_body = NULL;

	// lport/rport method
	if (data->user_data) {
		data->status = status;
		im_recv_resp_msg(data->user_data, rdata, status);
	} else {
		if ((status == PJ_SC_OK || status == PJ_SUCCESS) && 
			rdata->msg_info.msg->body) {
				resp_body = (pj_str_t *)malloc(sizeof(pj_str_t));
				resp_body->ptr = (char *)malloc(rdata->msg_info.msg->body->len);
				memcpy(resp_body->ptr, rdata->msg_info.msg->body->data, rdata->msg_info.msg->body->len);
				resp_body->slen = rdata->msg_info.msg->body->len;
		}

		data->status = status;
		data->user_data = (void *)resp_body;

		PJ_LOG(4, (THIS_FILE, "on_pager_status2() got response instant message. status=%d", status));

		pj_sem_post(data->waiting_sem);
	}
}

/*
 * Handler registration status has changed.
 */
static void on_reg_state(pjsua_inst_id inst_id, pjsua_acc_id acc_id)
{
    PJ_LOG(4, (THIS_FILE, "[call flow] on_reg_state()."));

	PJ_UNUSED_ARG(inst_id);
	PJ_UNUSED_ARG(acc_id);

    // Log already written.
}

#define SIP_RETRY_MAX_TIMES 4
#define SIP_RETRY_DELAY_BASE 240 //seconds
#define MAX_REG_DELAYED_SECONDS 3840 //seconds
#define MAX_REG_DELAYED_FOR_CIRCULAR_SECONDS 600

/*
	If MAX_COUNT=4, random_base=240 and random_max=3840, the return range will be.
	count=0, return 0
	count=1, return 240~480
	count=2, return 480~960
	count=3, return 960~1920
	count=4, return 1920~3840
*/
static int get_random_delay(int count, int random_base, int random_max) {
	int real_base;
	int random_delay;

	if (count < 1)
		return 0;

	if ((random_base<<count) > random_max)
		real_base = random_max - (random_base<<(count-1));
	else
		real_base = random_base<<(count-1);

	random_delay = (pj_rand() % real_base) + (random_base<<(count-1));
	PJ_LOG(4, (THIS_FILE, "get_random_delay, count=[%d], real_base=[%d], random_delay=[%d]", count, real_base, random_delay));
	return random_delay;
}

static void trigger_re_reg_timer (pjsua_inst_id inst_id) {
	pj_time_val delay = { 0, 0 };

	pj_init_random_seed();
	if (app_config[inst_id].curr_sip_idx+1 >= app_config[inst_id].natnl_cfg.sip_srv_cnt && 
		app_config[inst_id].sip_retry_cnt+1 > SIP_RETRY_MAX_TIMES)
		delay.sec = ((pj_rand() % MAX_REG_DELAYED_FOR_CIRCULAR_SECONDS) + MAX_REG_DELAYED_FOR_CIRCULAR_SECONDS);
	else
		delay.sec = get_random_delay(app_config[inst_id].sip_retry_cnt, SIP_RETRY_DELAY_BASE, MAX_REG_DELAYED_SECONDS);

	PJ_LOG(1,(THIS_FILE, "Trigger a timer to try next SIP for re-registration in %d s, count=%d", delay.sec, app_config[inst_id].sip_retry_cnt));

	pj_time_val_normalize(&delay);

	pjsip_endpt_cancel_timer(pjsua_var[inst_id].endpt, 
		&app_config[inst_id].re_reg_timer_entry);
	pjsip_endpt_schedule_timer(pjsua_var[inst_id].endpt, 
		&app_config[inst_id].re_reg_timer_entry, &delay);
}

static void trigger_one_day_reg_recovery_timer (pjsua_inst_id inst_id) {
	pj_time_val delay = { 86400, 0 }; // one day
	//pj_time_val delay = { 10, 0 }; // one day

	PJ_LOG(1,(THIS_FILE, "Trigger a one day timer try default SIP for re-registration in %d s", delay.sec));

	pj_time_val_normalize(&delay);

	pjsip_endpt_cancel_timer(pjsua_var[inst_id].endpt, 
		&app_config[inst_id].one_day_reg_recovery_timer_entry);
	pjsip_endpt_schedule_timer(pjsua_var[inst_id].endpt, 
		&app_config[inst_id].one_day_reg_recovery_timer_entry, &delay);
}

static int try_next_sip(pjsua_inst_id inst_id, pj_bool_t is_one_day_timer) {

	pjsua_transport_id transport_id = -1;
	pj_status_t status = PJ_SUCCESS;
	char *ch;
	int sip_idx = app_config[inst_id].curr_sip_idx;
	int retry = 1;

	if (is_one_day_timer) {
		pjsua_acc_set_registration(inst_id, current_acc(inst_id), PJ_FALSE);
		sip_idx = 0;
		app_config[inst_id].sip_retry_cnt = 1;
	}

	// Increment sip retry count.
	app_config[inst_id].sip_retry_cnt++;

	if (app_config[inst_id].sip_retry_cnt > SIP_RETRY_MAX_TIMES) {
		// If present sip is the last one, rotate it to first sip.
		if (++sip_idx > app_config[inst_id].natnl_cfg.sip_srv_cnt-1)
			sip_idx = 0;

		// Reset sip retry count for current sip.
		app_config[inst_id].sip_retry_cnt = 1;
		retry = 0;
	}

	app_config[inst_id].curr_sip_idx = sip_idx;

	// prepare tls sip-srv parameter
	if (ch = strstr(app_config[inst_id].natnl_cfg.sip_srv[sip_idx], ";transport=tls")) {
		app_config[inst_id].natnl_cfg.use_tls = 1;
		app_config[inst_id].use_tls = 1;
	}

	sprintf(app_config[inst_id].registrar_uri_str, "sip:%s", app_config[inst_id].natnl_cfg.sip_srv[sip_idx]);

	if (retry)
		PJ_LOG(1, (THIS_FILE, "Retry current sip server [%s] for retry_count=[%d]", 
			app_config[inst_id].registrar_uri_str, app_config[inst_id].sip_retry_cnt));
	else {
		PJ_LOG(1, (THIS_FILE, "Try next sip server [%s] for retry_count=[%d], is_one_day_timer=[%d]", 
			app_config[inst_id].registrar_uri_str, app_config[inst_id].sip_retry_cnt, is_one_day_timer));
	}

	app_config[inst_id].acc_cfg[current_acc(inst_id)].reg_retry_interval = 0; //DEAN. Retry registration by ourself.
	app_config[inst_id].acc_cfg[current_acc(inst_id)].reg_first_retry_interval = 60;

	pjsua_var[inst_id].acc[current_acc(inst_id)].cfg.reg_uri = pj_str(app_config[inst_id].registrar_uri_str);

	pjsua_acc_set_registration(inst_id, current_acc(inst_id), PJ_TRUE);

	return status;
}

static void on_reg_state2(pjsua_inst_id inst_id, pjsua_acc_id acc_id, pjsua_reg_info *info) {

	pjsip_cid_hdr *cid;
	int status = info->cbparam->code;

	struct natnl_data *user_data = NULL;
	pj_bool_t re_register_schd = PJ_FALSE;
#if 0
	char *status_s = nvram_get("aae_dbg_status");

	if (status_s)
		status = strtol(status_s, NULL, 10);
#endif
	PJ_UNUSED_ARG(acc_id);

	PJ_LOG(1, (THIS_FILE, "on_reg_state2() code=%d, status=%d\n", 
		info->cbparam->code, info->cbparam->status));

	// 2013-05-09 DEAN service is unavailable try another one
	if (status/100 == 5 || status == PJSIP_SC_REQUEST_TIMEOUT) {
		PJ_LOG(1, (THIS_FILE, "Failed(%d) connect to sip server [%s]", 
			status, app_config[inst_id].registrar_uri_str));
		if (app_config[inst_id].is_initializing ||
			app_config[inst_id].is_app_invoking_reg) { 
				if (app_config[inst_id].curr_sip_idx >= app_config[inst_id].natnl_cfg.sip_srv_cnt-1 &&
					app_config[inst_id].sip_retry_cnt >= SIP_RETRY_MAX_TIMES) {
					goto on_return; // don't retry circularly if app invoke or initialization stage registration.
				} else {
					//trigger_re_reg_timer(inst_id); // do it after calling callback
					re_register_schd = PJ_TRUE;
					goto on_return;
				}
		} else {
			//trigger_re_reg_timer(inst_id); // do it after calling callback
			re_register_schd = PJ_TRUE;
			goto on_return;
		}
	}

	// Reset current sip retry count.
	app_config[inst_id].sip_retry_cnt = 1;

	if ((app_config[inst_id].natnl_cfg.use_turn & TURN_FLAG_USE_UAC_TURN) > 0) {
		// natnl save register call-id as turn password
		if (info->cbparam->rdata) {
			cid = info->cbparam->rdata->msg_info.cid;

			pj_bzero(app_config[inst_id].reg_call_id, sizeof(app_config[inst_id].reg_call_id));
			strncpy(app_config[inst_id].reg_call_id, cid->id.ptr, cid->id.slen);
			PJ_LOG(4, (THIS_FILE, "on_reg_state2() REGISTER CALL-ID=%.*s", 
				cid->id.slen, cid->id.ptr));
		}
	}

on_return:
	user_data = (struct natnl_data *)app_config[inst_id].user_data;

	if ((app_config[inst_id].is_initializing || app_config[inst_id].register_only) &&
		!re_register_schd) {
		// prepare natnl_data and post semaphore
		if (user_data && user_data->waiting_sem) {
			user_data->status = status;
			pj_sem_post(user_data->waiting_sem);
		}
	}

	// DEAN call callback
	if (natnl_callback.on_natnl_tnl_event) {
		struct natnl_tnl_event tnl_event;
		memset(&tnl_event, 0, sizeof(tnl_event));
		tnl_event.inst_id = inst_id;
		if (tnl_event.inst_id >= 1)
			tnl_event.app_data = app_config[tnl_event.inst_id].app_data;
		tnl_event.call_id = -1;

		tnl_event.status_code = (natnl_status_code)info->cbparam->code;

		// 2013-03-21 DEAN Added, for new register or un-register event 
		if (info->cbparam->expiration == 0) {
			if (tnl_event.status_code == PJ_SUCCESS ||
				tnl_event.status_code == PJ_SC_OK)
				tnl_event.event_code = NATNL_TNL_EVENT_UNREG_OK;
			else
				tnl_event.event_code = NATNL_TNL_EVENT_UNREG_FAILED;
			if (info->cbparam->reason.slen > 0 && info->cbparam->reason.ptr) {
				my_memcpy(tnl_event.status_text, info->cbparam->reason.ptr, 
					sizeof(tnl_event.status_text), info->cbparam->reason.slen);
			}
		} else {
			if (tnl_event.status_code == PJ_SUCCESS ||
				tnl_event.status_code == PJ_SC_OK) {
				tnl_event.event_code = NATNL_TNL_EVENT_REG_OK;
			} else {
				tnl_event.event_code = NATNL_TNL_EVENT_REG_FAILED;
				if (info->cbparam->reason.slen > 0 && info->cbparam->reason.ptr) {
					my_memcpy(tnl_event.status_text, info->cbparam->reason.ptr, 
						sizeof(tnl_event.status_text), info->cbparam->reason.slen);
				}
			}
		}
		natnl_call_callback(&tnl_event);
#if 0
		// 2013-05-21 DEAN. Don't wait nat type detection.
		if (app_config[inst_id].is_initializing &&
			tnl_event.event_code == NATNL_TNL_EVENT_REG_OK &&
			pjsua_var[inst_id].mutex /*&&
			(//(!app_config[inst_id].upnp.inited && 
			 // app_config[inst_id].upnp_port_mapping_cnt == 0 ) || 
			  (app_config[inst_id].upnp.inited && 
			  app_config[inst_id].upnp_port_mapping_cnt == app_config[inst_id].cfg.max_calls))*/) {
			tnl_event.event_code = NATNL_TNL_EVENT_INIT_OK;
			app_config[inst_id].is_initializing = PJ_FALSE;
			natnl_call_callback(&tnl_event);
		}
#endif
		if (tnl_event.event_code == NATNL_TNL_EVENT_REG_OK)
			app_config[inst_id].reg_ok = PJ_TRUE;

#if 0
		if (app_config[inst_id].is_initializing &&
			!app_config[inst_id].register_only &&
			info->cbparam->expiration != 0 &&
			tnl_event.status_code != PJ_SUCCESS &&
			tnl_event.status_code != PJ_SC_OK) {
				tnl_event.event_code = NATNL_TNL_EVENT_INIT_FAILED;
				//natnl_callback.on_natnl_tnl_event(&tnl_event);
				app_config[inst_id].is_initializing = PJ_FALSE;
				natnl_call_callback(&tnl_event);
				return;
		}
#endif
	}

	if (re_register_schd) 
	{
		// Check if one day recovery timer is running.
		// If true, try the default SIP and cancel the one day recovery timer.
		if (pj_timer_entry_running(&app_config[inst_id].one_day_reg_recovery_timer_entry)) {
			pjsip_endpt_cancel_timer(pjsua_var[inst_id].endpt, 
				&app_config[inst_id].one_day_reg_recovery_timer_entry);
			app_config[inst_id].curr_sip_idx == 0;
			PJ_LOG(1,(THIS_FILE, "One day recovery timer is running. Cancel it!!!"));
			PJ_LOG(1,(THIS_FILE, "Set current sip index to %d. For trying default SIP.", app_config[inst_id].curr_sip_idx));
		}
		trigger_re_reg_timer(inst_id);
	} // 2017-06-09. If current connected server is not default SIP, trigger a one day timer to recover it.
	else if (status == 200) 
	{
		pjsip_endpt_cancel_timer(pjsua_var[inst_id].endpt, 
			&app_config[inst_id].one_day_reg_recovery_timer_entry);
		if (app_config[inst_id].curr_sip_idx != 0 || info->cbparam->expiration == 0)
			trigger_one_day_reg_recovery_timer(inst_id);
	}
}

/*
 * Transport status notification
 */
static void on_transport_state(pjsip_transport *tp, 
                               pjsip_transport_state state,
                               const pjsip_transport_state_info *info)
{
    PJ_LOG(4, (THIS_FILE, "[call flow] on_transport_state()."));

    char host_port[128];
	pjsua_inst_id inst_id = tp->pool->factory->inst_id;

	pj_ansi_snprintf(host_port, sizeof(host_port), "[%.*s:%d]",
                     (int)tp->remote_name.host.slen,
                     tp->remote_name.host.ptr,
                     tp->remote_name.port);

    switch (state) {
    case PJSIP_TP_STATE_CONNECTED:
        {
            PJ_LOG(3,(THIS_FILE, "SIP %s transport is connected to %s",
                     tp->type_name, host_port));
        }
        break;

    case PJSIP_TP_STATE_DISCONNECTED:
		{

            char buf[100];

            snprintf(buf, sizeof(buf), "SIP %s transport is disconnected from %s",
                     tp->type_name, host_port);

            pjsua_perror(THIS_FILE, buf, info->status);

			if (app_config[inst_id].natnl_cfg.is_server_side_app && 
				!app_config[inst_id].is_initializing && 
				!app_config[inst_id].is_app_invoking_reg)
			{
				// Check if one day recovery timer is running.
				// If true, try the default SIP and cancel the one day recovery timer.
				if (pj_timer_entry_running(&app_config[inst_id].one_day_reg_recovery_timer_entry)) {
					pjsip_endpt_cancel_timer(pjsua_var[inst_id].endpt, 
						&app_config[inst_id].one_day_reg_recovery_timer_entry);
					app_config[inst_id].curr_sip_idx = 0;
					PJ_LOG(1,(THIS_FILE, "One day recovery timer is running. Cancel it!!!"));
					PJ_LOG(1,(THIS_FILE, "Set current sip index to %d. For trying default SIP.", app_config[inst_id].curr_sip_idx));
				}
				trigger_re_reg_timer(inst_id);
			}
        }
        break;

    default:
        break;
    }

#if defined(PJSIP_HAS_TLS_TRANSPORT) && PJSIP_HAS_TLS_TRANSPORT!=0

    if (!pj_ansi_stricmp(tp->type_name, "tls") && info->ext_info &&
        (state == PJSIP_TP_STATE_CONNECTED || 
         ((pjsip_tls_state_info*)info->ext_info)->
                                 ssl_sock_info->verify_status != PJ_SUCCESS))
    {
        pjsip_tls_state_info *tls_info = (pjsip_tls_state_info*)info->ext_info;
        pj_ssl_sock_info *ssl_sock_info = tls_info->ssl_sock_info;
        char buf[2048];
        const char *verif_msgs[32];
        unsigned verif_msg_cnt;

        /* Dump server TLS certificate */
        pj_ssl_cert_info_dump(ssl_sock_info->remote_cert_info, "  ",
                              buf, sizeof(buf));
        PJ_LOG(4,(THIS_FILE, "TLS cert info of %s:\n%s", host_port, buf));

        /* Dump server TLS certificate verification result */
        verif_msg_cnt = PJ_ARRAY_SIZE(verif_msgs);
        pj_ssl_cert_get_verify_status_strings(ssl_sock_info->verify_status,
                                              verif_msgs, &verif_msg_cnt);
        PJ_LOG(3,(THIS_FILE, "TLS cert verification result of %s : %s",
                             host_port,
                             (verif_msg_cnt == 1? verif_msgs[0]:"")));
        if (verif_msg_cnt > 1) {
            unsigned i;
            for (i = 0; i < verif_msg_cnt; ++i)
                PJ_LOG(3,(THIS_FILE, "- %s", verif_msgs[i]));
        }

        if (ssl_sock_info->verify_status &&
            !app_config[inst_id].udp_cfg.tls_setting.verify_server) 
        {
            PJ_LOG(3,(THIS_FILE, "PJSUA is configured to ignore TLS cert "
                                 "verification errors"));
        }
    }

#endif

}

/* Callback from timer when the maximum call duration has been
 * exceeded.
 */
static void call_timeout_callback(pj_timer_heap_t *timer_heap,
                                  struct pj_timer_entry *entry)
{
    PJ_LOG(4, (THIS_FILE, "[call flow] call_timeout_callback()."));

	pjsua_call *call = ((pjsua_call *)entry->user_data);
	pjsua_inst_id inst_id = call->inst_id;
    pjsua_call_id call_id = call->index;
    pjsua_msg_data msg_data;
    pjsip_generic_string_hdr warn;
    pj_str_t hname = pj_str("Warning");
	pj_str_t hvalue = pj_str("399 pjsua \"Call duration exceeded\"");

	struct natnl_data *user_data = (struct natnl_data *)call->user_data;
    PJ_UNUSED_ARG(timer_heap);

    if (call_id == PJSUA_INVALID_ID) {
        PJ_LOG(1, (THIS_FILE, "Invalid call ID in timer callback"));
        return;
    }
    
    /* Add warning header */
    pjsua_msg_data_init(&msg_data);
    pjsip_generic_string_hdr_init2(&warn, &hname, &hvalue);
    pj_list_push_back(&msg_data.hdr_list, &warn);

    /* Call duration has been exceeded; disconnect the call */
    PJ_LOG(3,(THIS_FILE, "Duration (%d seconds) has been exceeded "
                         "for call %d, disconnecting the call",
                         app_config[inst_id].duration, call_id));

    entry->id = PJSUA_INVALID_ID;
	pjsua_call_hangup(inst_id, call_id, NATNL_SC_MAKE_CALL_TIMEOUT, NULL, &msg_data);
}

static void trigger_re_inv_timer (pjsua_inst_id inst_id, pjsua_call_id call_id, int delay_sec) {
	pj_time_val delay = { delay_sec, 0 };
	pj_time_val_normalize(&delay);

	pjsip_endpt_cancel_timer(pjsua_var[inst_id].endpt, 
		&app_config[inst_id].re_inv_timer_entry[call_id]);
	pjsip_endpt_schedule_timer(pjsua_var[inst_id].endpt, 
		&app_config[inst_id].re_inv_timer_entry[call_id], &delay);
}

static void try_next_inv_sip(pjsua_inst_id inst_id, pjsua_call_id call_id) {

	pjsua_transport_id transport_id = -1;
	pj_status_t status = PJ_SUCCESS;
	char *ch;
	int sip_idx = app_config[inst_id].curr_sip_idx;
	int retry = 1;

	pjsua_msg_data msg_data;
	char dest_uri[256];
	char uri_to_be_called[128];
	char *dest_uri_tmp;
	pj_str_t tmp;
	pjsua_call_id id = call_id; //Initial call_id value to original one for re-using the call_id.

	pjsua_call *call = &pjsua_var[inst_id].calls[call_id];

	// Retrieve callee device id from dest_uri
	memset(dest_uri, 0, sizeof(dest_uri));
	my_memcpy(dest_uri, app_config[inst_id].re_inv_info[call_id].dest_uri, sizeof(dest_uri), 
		strlen(app_config[inst_id].re_inv_info[call_id].dest_uri));

	dest_uri_tmp = strtok(dest_uri, "@");

	if (app_config[inst_id].sip_re_inv_cnt[call_id] >= app_config[inst_id].natnl_cfg.sip_srv_cnt)  {
		goto on_return;
		return; // It means every sip was tried. We should terminate retry mechanism.
	}

	app_config[inst_id].curr_re_inv_sip_idx[call_id]++;
	if (app_config[inst_id].curr_re_inv_sip_idx[call_id] > (app_config[inst_id].natnl_cfg.sip_srv_cnt-1)) { 
		app_config[inst_id].curr_re_inv_sip_idx[call_id] = 0; // It means that sip index rotation is needed.
	}

	pjsua_msg_data_init(&msg_data);
	if (dest_uri_tmp) {
		sprintf(uri_to_be_called, "%s@%s", dest_uri_tmp, 
			app_config[inst_id].natnl_cfg.sip_srv[app_config[inst_id].curr_re_inv_sip_idx[call_id]]);
		tmp = pj_str(uri_to_be_called);
		status = pjsua_call_make_call( inst_id, current_acc(inst_id), &tmp, 0, call->use_sctp, (void*) "user_id", &msg_data, &id);
		if (status == PJ_SUCCESS) {
			app_config[inst_id].sip_re_inv_cnt[call_id]++;
			return;
		}
	}

on_return:
{
	struct natnl_data *user_data = (struct natnl_data *)&app_config[inst_id].call_user_data[call_id];

	// prepare natnl_data and post semaphore
	if (user_data && user_data->waiting_sem) {
		user_data->status = status;
		pj_sem_post(user_data->waiting_sem);
	}
}
}

static void re_inv_func(pj_timer_heap_t *th, struct pj_timer_entry *te)
{
	struct inv_info *re_inv_info = (struct inv_info*)te->user_data;
	try_next_inv_sip(re_inv_info->inst_id, re_inv_info->call_id);
}

/*
 * Handler when invite state has changed.
 */
static void on_call_state(pjsua_inst_id inst_id, pjsua_call_id call_id, pjsip_event *e)
{
	pjsua_call *call = &pjsua_var[inst_id].calls[call_id];
	struct natnl_data *user_data = (struct natnl_data *)&app_config[inst_id].call_user_data[call_id];
	pj_str_t state_text;
	pjsip_inv_state state = PJSIP_INV_STATE_NULL;
	int role = -1;

	if (call->inv) {
		state = call->inv->state;
		state_text = pj_str((char*)pjsip_inv_state_name(state));
		role = call->inv->role;
	}

    PJ_LOG(4, (THIS_FILE, "[call flow] on_call_state()."));

#if defined(PJMEDIA_HAS_SRTP) && (PJMEDIA_HAS_SRTP != 0)
	struct transport_srtp *tp_srtp = (struct transport_srtp *)call->med_tp;
	struct pjmedia_transport *tp = 
		(struct pjmedia_transport *)pjmedia_transport_srtp_get_member((pjmedia_transport *)tp_srtp);
#elif defined(PJMEDIA_HAS_DTLS) && (PJMEDIA_HAS_DTLS != 0)
	#if defined(PJMEDIA_DISABLE_SCTP) && (PJMEDIA_DISABLE_SCTP != 0) // sctp disabled
		struct pjmedia_transport *tp_dtls =(struct pjmedia_transport *)call->med_tp;
		struct pjmedia_transport *tp = 
			(struct pjmedia_transport *)pjmedia_transport_dtls_get_member((pjmedia_transport *)tp_dtls);
	#else
		struct pjmedia_transport *tp_sctp = (struct pjmedia_transport *)call->med_tp;
		struct pjmedia_transport *tp_dtls = 
			(struct pjmedia_transport *)pjmedia_transport_sctp_get_member((pjmedia_transport *)tp_sctp);
		struct pjmedia_transport *tp = 
			(struct pjmedia_transport *)pjmedia_transport_dtls_get_member((pjmedia_transport *)tp_dtls);
	#endif
#else
	struct pjmedia_transport *tp = call->med_tp;
#endif

    PJ_UNUSED_ARG(e);

    PJ_LOG(4, (THIS_FILE, "on_call_state(). state=[%d]", state));

	// DEAN. SIP is unavailable or request timeout, try next sip server.
	if (tp && tp->dest_uri && 
		((call->last_code / 100) == 5) && 
		(app_config[inst_id].sip_re_inv_cnt[call_id] < app_config[inst_id].natnl_cfg.sip_srv_cnt)) {
			if (app_config[inst_id].call_hangup_request[call_id] == 0) {
				PJ_LOG(3,(THIS_FILE, "Trigger a timer to try next sip for making call in 1 second."));
				trigger_re_inv_timer(inst_id, call_id, 1);
				return;
			} else {
				PJ_LOG(4, (__FILE__, "there is pending hangup. Stop retry SIP inst_id=[%d], call_id=[%d]", 
					inst_id, call_id));
			}
	}

	if (state == PJSIP_INV_STATE_DISCONNECTED) {
        PJ_LOG(5, (THIS_FILE, "on_call_state(). PJSIP_INV_STATE_DISCONNECTED"));

        /* Stop all ringback for this call */
        //ring_stop(call_id);

        /* Cancel duration timer, if any */
        if (app_config[inst_id].call_data[call_id].timer.id != PJSUA_INVALID_ID) {
            struct call_data *cd = &app_config[inst_id].call_data[call_id];
            pjsip_endpoint *endpt = pjsua_get_pjsip_endpt(inst_id);

            cd->timer.id = PJSUA_INVALID_ID;
            pjsip_endpt_cancel_timer(endpt, &cd->timer);

            PJ_LOG(4, (THIS_FILE, "making call timeout check timer cancelled."));
		}

		if (pjsua_var[inst_id].calls[call_id].current_action == 1) { // on call making, should report make call ailed.
			// prepare natnl_data and post semaphore
			if (user_data && user_data->waiting_sem) {
				user_data->status = call->last_code;

				app_config[inst_id].call_hangup_request[call_id] = 0;

				pj_sem_post(user_data->waiting_sem);
			}

			// DEAN call callback
			if (natnl_callback.on_natnl_tnl_event) {
				struct natnl_tnl_event tnl_event;

				memset(&tnl_event, 0, sizeof(tnl_event));
				tnl_event.inst_id = inst_id;
				if (tnl_event.inst_id >= 1)
					tnl_event.app_data = app_config[tnl_event.inst_id].app_data;
				tnl_event.call_id = call_id;

				if (state_text.slen > 0 && state_text.ptr) {
					my_memcpy(tnl_event.event_text, state_text.ptr, 
						sizeof(tnl_event.event_text), state_text.slen);
				}
				tnl_event.status_code = (natnl_status_code)call->last_code;
				if (tnl_event.status_code != PJ_SC_OK) {
					tnl_event.event_code = NATNL_TNL_EVENT_MAKECALL_FAILED;
				}

				if (tnl_event.status_code == PJ_SC_SERVICE_UNAVAILABLE && 
					pj_strcmp2(&call->last_text, "Operation timed out (PJ_ETIMEDOUT)") == 0) {
						tnl_event.status_code = NATNL_SC_CONNECT_TO_SIP_TIMEOUT;
				}

				if (call->last_text.slen > 0 && call->last_text.ptr) {
					my_memcpy(tnl_event.status_text, call->last_text.ptr, 
						sizeof(tnl_event.status_text), call->last_text.slen);
				}

				//if (call->inv && call->inv->dlg)
				//	pjsip_dlg_inc_lock(call->inv->dlg); // lock dlg

				if (call->inv && call->inv->dlg->call_id->id.slen > 0 && call->inv->dlg->call_id->id.ptr) {
					my_memcpy(tnl_event.session_id, call->inv->dlg->call_id->id.ptr, 
						sizeof(tnl_event.session_id), call->inv->dlg->call_id->id.slen);
				}

				// DEAN Added 2013-03-15
				if (call->inv && call->inv->dlg->remote.ua_str.slen > 0 && call->inv->dlg->remote.ua_str.ptr) {
					my_memcpy(tnl_event.para.remote_info.version, call->inv->dlg->remote.ua_str.ptr, 
						sizeof(tnl_event.para.remote_info.version), call->inv->dlg->remote.ua_str.slen);
				}
				//if (call->inv && call->inv->dlg)
				//	pjsip_dlg_dec_lock(call->inv->dlg); // unlock dlg

				tnl_event.ua_type = role+1;

				if (tp)
				{
					char tmp[64];
					memset(tmp, 0, sizeof(tmp));
					pjmedia_transport_get_remote_userid(tp, tmp);

					my_memcpy(tnl_event.para.remote_info.user_id, tmp, 
						sizeof(tnl_event.para.remote_info.user_id), strlen(tmp));
				}

				// device_id
				if (tp)
				{
					char full_device_id[128];
					char *device_id;
					memset(full_device_id, 0, sizeof(full_device_id));
					if (tnl_event.ua_type == 1) // UAC
					{
						if (tp->dest_uri)
						{
							pj_str_t *dest_uri = tp->dest_uri;
							strncpy(full_device_id, dest_uri->ptr, dest_uri->slen);
						}
					}
					else // UAS
					{
						pjmedia_transport_get_remote_deviceid(tp, full_device_id);
					}
					device_id = get_id_part_device_id(full_device_id);
					if (device_id)
						my_memcpy(tnl_event.para.remote_info.device_id, device_id, 
						sizeof(tnl_event.para.remote_info.device_id), strlen(device_id));
				}

				// DEAN Added 2013-03-15
				if (pjsua_var[inst_id].ua_cfg.user_agent.slen > 0 && pjsua_var[inst_id].ua_cfg.user_agent.ptr) {
					my_memcpy(tnl_event.para.local_info.version, pjsua_var[inst_id].ua_cfg.user_agent.ptr, 
						sizeof(tnl_event.para.local_info.version), pjsua_var[inst_id].ua_cfg.user_agent.slen);
				}

				//natnl_callback.on_natnl_tnl_event(&tnl_event);
				natnl_call_callback(&tnl_event);
			}
		}

        PJ_LOG(3,(THIS_FILE, "Call %d is DISCONNECTED [reason=%d (%s)]", 
                  call_id,
                  call->last_code,
                  call->last_text.ptr));

        if (call_id == app_config[inst_id].current_call) {
            find_next_call(inst_id);
        }

        /* Dump media state upon disconnected */
        if (1) {
            PJ_LOG(5,(THIS_FILE, 
                      "Call %d disconnected, dumping media stats..", 
                      call_id));
            log_call_dump(inst_id, call_id);
        }

    } else {
		// Check SCTP support for remote peer.
		if (role == PJSIP_ROLE_UAC && 
			state == PJSIP_INV_STATE_CONNECTING) {
			pjsip_tnl_supported_hdr *tnl_sup_hdr;
			pj_bool_t sctp_supported = PJ_FALSE;

#if defined(PJMEDIA_DISABLE_SCTP) && (PJMEDIA_DISABLE_SCTP != 0) // sctp disabled
			call->use_sctp = 0;
			call->med_tp->use_sctp = 0;    // sctp
			if (call->med_orig)
				call->med_orig->use_sctp = 0;  // dtls
#else
			/* Check Supported header */
			tnl_sup_hdr = (pjsip_tnl_supported_hdr*)
				pjsip_msg_find_hdr(e->body.rx_msg.rdata->msg_info.msg, PJSIP_H_TNL_SUPPORTED, NULL);
			if (tnl_sup_hdr) {
				unsigned i;
				const pj_str_t STR_SCTP = { "SCTP", 4};

				for (i=0; i<tnl_sup_hdr->count; ++i) {
					if (pj_stricmp(&tnl_sup_hdr->values[i], &STR_SCTP)==0) {
						sctp_supported = PJ_TRUE;
						break;
					}
				}
				if (!sctp_supported) {
					call->use_sctp = 0;
					call->med_tp->use_sctp = 0;    // sctp
					if (call->med_orig)
						call->med_orig->use_sctp = 0;  // dtls
				}
			} else {
				call->use_sctp = 0;
				call->med_tp->use_sctp = 0;    // sctp
				if (call->med_orig)
					call->med_orig->use_sctp = 0;  // dtls
			}
#endif
		}

        if (state == PJSIP_INV_STATE_EARLY) {
            int code;
            pj_str_t reason;
            pjsip_msg *msg;

            /* This can only occur because of TX or RX message */
            pj_assert(e->type == PJSIP_EVENT_TSX_STATE);

            if (e->body.tsx_state.type == PJSIP_EVENT_RX_MSG) {
                msg = e->body.tsx_state.src.rdata->msg_info.msg;
            } else {
                msg = e->body.tsx_state.src.tdata->msg;
            }

            code = msg->line.status.code;
            reason = msg->line.status.reason;

            /* Start ringback for 251 for UAC unless there's SDP in 251 */
            if (role==PJSIP_ROLE_UAC && code==251 && 
                msg->body == NULL && 
                call->media_st==PJSUA_CALL_MEDIA_NONE) {
                //ringback_start(call_id);
            }

            PJ_LOG(3,(THIS_FILE, "Call %d state changed to %s (%d %.*s)", 
                      call_id, state_text.ptr,
                      code, (int)reason.slen, reason.ptr));
        } else {
            PJ_LOG(3,(THIS_FILE, "Call %d state changed to %s", 
                      call_id,
                      state_text.ptr));
        }

        if (app_config[inst_id].current_call==PJSUA_INVALID_ID)
            app_config[inst_id].current_call = call_id;

    }
}


/**
 * Handler when there is incoming call.
 */
static void on_incoming_call(pjsua_inst_id inst_id, 
							 pjsua_acc_id acc_id, pjsua_call_id call_id,
                             pjsip_rx_data *rdata)
{
	pjsua_call *call = &pjsua_var[inst_id].calls[call_id];

    PJ_LOG(4, (THIS_FILE, "[call flow] on_incoming_call(). call_id=[%d].", call_id));

    PJ_UNUSED_ARG(acc_id);
    PJ_UNUSED_ARG(rdata);

    if (app_config[inst_id].current_call==PJSUA_INVALID_ID)
        app_config[inst_id].current_call = call_id;

#ifdef USE_GUI
    if (!showNotification(call_id))
        return;
#endif

    /* Start ringback */
    //ring_start(call_id);
    
    if (app_config[inst_id].auto_answer > 0) {
        pjsua_call_answer(inst_id, call_id, app_config[inst_id].auto_answer, NULL, NULL);
    }

	if (app_config[inst_id].auto_answer < 200) {
		//if (call->inv && call->inv->dlg)
		//	pjsip_dlg_inc_lock(call->inv->dlg); // lock dlg

        PJ_LOG(3,(THIS_FILE,
                  "Incoming call for account %d!\n"
                  "From: %s\n"
                  "To: %s\n"
                  "Press a to answer or h to reject call",
                  acc_id,
                  call->inv->dlg->remote.info_str.ptr,
				  call->inv->dlg->local.info_str.ptr));

		//if (call->inv && call->inv->dlg)
		//	pjsip_dlg_dec_lock(call->inv->dlg); // unlock dlg
    }
}

/*
 * Handler when a transaction within a call has changed state.
 */
static void on_call_tsx_state(pjsua_inst_id inst_id,
							  pjsua_call_id call_id,
                              pjsip_transaction *tsx,
                              pjsip_event *e)
{
    PJ_LOG(4, (THIS_FILE, "[call flow] on_call_tsx_state(). call_id=[%d].", call_id));

    const pjsip_method info_method = 
    {
        PJSIP_OTHER_METHOD,
        { "INFO", 4 }
	};

	const pjsip_method bye_method =
	{
		PJSIP_BYE_METHOD,
		{ "BYE", 3 }
	};

	const pjsip_method update_method =
	{
		PJSIP_OTHER_METHOD,
		{ "UPDATE", 6 }
	};

    if (pjsip_method_cmp(&tsx->method, &info_method)==0) {
        /*
         * Handle INFO method.
         */
        if (tsx->role == PJSIP_ROLE_UAC && 
            (tsx->state == PJSIP_TSX_STATE_COMPLETED ||
             (tsx->state == PJSIP_TSX_STATE_TERMINATED &&
              e->body.tsx_state.prev_state != PJSIP_TSX_STATE_COMPLETED))) {
            /* Status of outgoing INFO request */
            if (tsx->status_code >= 200 && tsx->status_code < 300) {
                PJ_LOG(4,(THIS_FILE, 
                          "Call %d: DTMF sent successfully with INFO",
                          call_id));
            } else if (tsx->status_code >= 300) {
                PJ_LOG(4,(THIS_FILE, 
                          "Call %d: Failed to send DTMF with INFO: %d/%.*s",
                          call_id,
                          tsx->status_code,
                          (int)tsx->status_text.slen,
                          tsx->status_text.ptr));
            }
        } else if (tsx->role == PJSIP_ROLE_UAS &&
                   tsx->state == PJSIP_TSX_STATE_TRYING) {
            /* Answer incoming INFO with 200/OK */
            pjsip_rx_data *rdata;
            pjsip_tx_data *tdata;
            pj_status_t status;

            rdata = e->body.tsx_state.src.rdata;

            if (rdata->msg_info.msg->body) {
                status = pjsip_endpt_create_response(tsx->endpt, rdata,
                                                     200, NULL, &tdata);
                if (status == PJ_SUCCESS)
                    status = pjsip_tsx_send_msg(tsx, tdata);

                PJ_LOG(3,(THIS_FILE, "Call %d: incoming INFO:\n%.*s", 
                          call_id,
                          (int)rdata->msg_info.msg->body->len,
                          rdata->msg_info.msg->body->data));
            } else {
                status = pjsip_endpt_create_response(tsx->endpt, rdata,
                                                     400, NULL, &tdata);
                if (status == PJ_SUCCESS)
                    status = pjsip_tsx_send_msg(tsx, tdata);
            }
        }
    } else if (pjsip_method_cmp(&tsx->method, &bye_method)==0) {
        //printf("[main.c] on_call_tsx_state tsx->role=[%d], tsx->state=[%d]\n", tsx->role, tsx->state);
	} 
}

static void on_call_media_destroy(pjsua_inst_id inst_id, pjsua_call_id call_id)
{
	pjsua_call *call = &pjsua_var[inst_id].calls[call_id];
	struct natnl_data *user_data = (struct natnl_data *)&app_config[inst_id].call_user_data[call_id];
	pj_str_t state_text;
	pjsip_inv_state state = PJSIP_INV_STATE_NULL;
	int role = -1;
    pj_status_t status;
	void *stcp_sock;
	void *sctp_accept_sock;

	PJ_LOG(4, (THIS_FILE, "call=%p. call->tnl_stream=%p", call, call->tnl_stream));
	if (!call || !call->tnl_stream)
		return;

	call->tnl_stream->thread_quit_flag = 1;
	if (!call->med_tp->use_sctp) {
		PJ_LOG(4, (THIS_FILE, "enter udt_close."));
		udt_close(call);
		PJ_LOG(4, (THIS_FILE, "leave udt_close."));
	}

	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 1"));
	pj_sem_post(call->tnl_stream->rbuff_sem);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 2"));
	pj_sem_post(call->tnl_stream->no_ctl_rbuff_sem);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 3"));
	//pj_sem_destroy(call->tnl_stream->rbuff_sem);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 4"));
	pj_mutex_lock(call->tnl_stream_lock);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 5"));
	pj_sem_post(call->tnl_stream->rbuff_sem);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 6"));
	pj_sem_post(call->tnl_stream->no_ctl_rbuff_sem);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 7"));
	pj_mutex_lock(call->tnl_stream_lock2);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 8"));
	pj_sem_post(call->tnl_stream->rbuff_sem);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 9"));
	pj_sem_post(call->tnl_stream->no_ctl_rbuff_sem);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 10"));

	// destroy natnl thread
	if (call->tnl_stream->send_thread) 
	{
		PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 11"));
		pj_thread_join(call->tnl_stream->send_thread);
		PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 12"));
		pj_thread_destroy(call->tnl_stream->send_thread);
		PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 13"));
		call->tnl_stream->send_thread = NULL;
	}
	if (call->tnl_stream->recv_thread) 
	{
		PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 14"));
		pj_thread_join(call->tnl_stream->recv_thread);
		PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 15"));
		pj_thread_destroy(call->tnl_stream->recv_thread);
		PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 16"));
		call->tnl_stream->recv_thread = NULL;
	}
	if (call->tnl_stream->no_ctl_recv_thread) 
	{
		PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 17"));
		pj_thread_join(call->tnl_stream->no_ctl_recv_thread);
		PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 18"));
		pj_thread_destroy(call->tnl_stream->no_ctl_recv_thread);
		PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 19"));
		call->tnl_stream->no_ctl_recv_thread = NULL;
	}

	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 20"));
	pjmedia_natnl_stream_destroy(call->tnl_stream);
	//call->tnl_stream = NULL;

	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 21"));
	status = tunnel_destroy(inst_id, call_id);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 22"));
	if (status != PJ_SUCCESS) {
		PJ_LOG(2, (THIS_FILE, "on_call_state() Unable to destroy tunnel. "
			"status=[%d]", status));
	}

	if (call->inv) {
		state = call->inv->state;
		state_text = pj_str((char*)pjsip_inv_state_name(state));
		role = call->inv->role;
	}

#if defined(PJMEDIA_HAS_SRTP) && (PJMEDIA_HAS_SRTP != 0)
	struct transport_srtp *tp_srtp = (struct transport_srtp *)call->med_tp;
	struct pjmedia_transport *tp = 
		(struct pjmedia_transport *)pjmedia_transport_srtp_get_member((pjmedia_transport *)tp_srtp);
#elif defined(PJMEDIA_HAS_DTLS) && (PJMEDIA_HAS_DTLS != 0)
	#if defined(PJMEDIA_DISABLE_SCTP) && (PJMEDIA_DISABLE_SCTP != 0) // sctp disabled
		struct pjmedia_transport *tp_dtls =(struct pjmedia_transport *)call->med_tp;
		struct pjmedia_transport *tp = 
			(struct pjmedia_transport *)pjmedia_transport_dtls_get_member((pjmedia_transport *)tp_dtls);
	#else
		struct pjmedia_transport *tp_sctp = (struct pjmedia_transport *)call->med_tp;
		struct pjmedia_transport *tp_dtls = 
			(struct pjmedia_transport *)pjmedia_transport_sctp_get_member((pjmedia_transport *)tp_sctp);
		struct pjmedia_transport *tp = 
			(struct pjmedia_transport *)pjmedia_transport_dtls_get_member((pjmedia_transport *)tp_dtls);
	#endif
#else
	struct pjmedia_transport *tp = call->med_tp;
#endif

	if (pjsua_var[inst_id].calls[call_id].current_action == 2) { // on call, should report hangup ok/failed.
		// prepare natnl_data and post semaphore
		if (user_data && user_data->waiting_sem) {
			// To avoid natnl_read_tnl_status return another status code.
			if (call->inv && call->inv->cause == NATNL_SC_TNL_TIMEOUT)
				user_data->status = NATNL_SC_TNL_TIMEOUT;
			else
			    user_data->status = call->last_code;

			app_config[inst_id].call_hangup_request[call_id] = 0;

			pj_sem_post(user_data->waiting_sem);
		}

		// DEAN call callback
		if (natnl_callback.on_natnl_tnl_event) {
			struct natnl_tnl_event tnl_event;

			memset(&tnl_event, 0, sizeof(tnl_event));
			tnl_event.inst_id = inst_id;
			if (tnl_event.inst_id >= 1)
				tnl_event.app_data = app_config[tnl_event.inst_id].app_data;
			tnl_event.call_id = call_id;

			if (state_text.slen > 0 && state_text.ptr) {
				my_memcpy(tnl_event.event_text, state_text.ptr, 
					sizeof(tnl_event.event_text), state_text.slen);
			}
			tnl_event.status_code = (natnl_status_code)call->last_code;
			if (tnl_event.status_code != PJ_SC_OK) {
				// reset call_hangup_request
				app_config[inst_id].call_hangup_request[call_id] = 0;

				tnl_event.event_code = NATNL_TNL_EVENT_HANGUP_OK;
			}

			if (tnl_event.status_code == PJ_SC_SERVICE_UNAVAILABLE && 
				pj_strcmp2(&call->last_text, "Operation timed out (PJ_ETIMEDOUT)") == 0) {
					tnl_event.status_code = NATNL_SC_CONNECT_TO_SIP_TIMEOUT;
			}

			if (call->last_text.slen > 0 && call->last_text.ptr) {
				my_memcpy(tnl_event.status_text, call->last_text.ptr, 
					sizeof(tnl_event.status_text), call->last_text.slen);
			}

			//if (call->inv && call->inv->dlg)
			//	pjsip_dlg_inc_lock(call->inv->dlg); // lock dlg

			if (call->inv && call->inv->dlg->call_id->id.slen > 0 && call->inv->dlg->call_id->id.ptr) {
				my_memcpy(tnl_event.session_id, call->inv->dlg->call_id->id.ptr, 
					sizeof(tnl_event.session_id), call->inv->dlg->call_id->id.slen);
			}

			// DEAN Added 2013-03-15
			if (call->inv && call->inv->dlg->remote.ua_str.slen > 0 && call->inv->dlg->remote.ua_str.ptr) {
				my_memcpy(tnl_event.para.remote_info.version, call->inv->dlg->remote.ua_str.ptr, 
					sizeof(tnl_event.para.remote_info.version), call->inv->dlg->remote.ua_str.slen);
			}

			//if (call->inv && call->inv->dlg)
			//	pjsip_dlg_dec_lock(call->inv->dlg); // unlock dlg

			tnl_event.ua_type = role+1;

			if (tp)
			{
				char tmp[64];
				memset(tmp, 0, sizeof(tmp));
				pjmedia_transport_get_remote_userid(tp, tmp);

				my_memcpy(tnl_event.para.remote_info.user_id, tmp, 
					sizeof(tnl_event.para.remote_info.user_id), strlen(tmp));
			}

			// device_id
			if (tp)
			{
				char full_device_id[128];
				char *device_id;
				memset(full_device_id, 0, sizeof(full_device_id));
				if (tnl_event.ua_type == 1) // UAC
				{
					if (tp->dest_uri)
					{
						pj_str_t *dest_uri = tp->dest_uri;
						strncpy(full_device_id, dest_uri->ptr, dest_uri->slen);
					}
				}
				else // UAS
				{
					pjmedia_transport_get_remote_deviceid(tp, full_device_id);
				}
				device_id = get_id_part_device_id(full_device_id);
				if (device_id)
					my_memcpy(tnl_event.para.remote_info.device_id, device_id, 
					sizeof(tnl_event.para.remote_info.device_id), strlen(device_id));
			}

			// DEAN Added 2013-03-15
			if (pjsua_var[inst_id].ua_cfg.user_agent.slen > 0 && pjsua_var[inst_id].ua_cfg.user_agent.ptr) {
				my_memcpy(tnl_event.para.local_info.version, pjsua_var[inst_id].ua_cfg.user_agent.ptr, 
					sizeof(tnl_event.para.local_info.version), pjsua_var[inst_id].ua_cfg.user_agent.slen);
			}

			//natnl_callback.on_natnl_tnl_event(&tnl_event);
			natnl_call_callback(&tnl_event);

			if (tnl_event.status_code == PJ_SC_OK) {
				//if (pjsua_var.calls[call_id].current_action == 1)
				//    tnl_event.event_code = NATNL_TNL_EVENT_MAKECALL_FAILED;
				//else if (pjsua_var.calls[call_id].current_action == 2)
				// 2013-10-24 DEAN. If it is make call ok action, then notify hangup ok
				// If it is make call failed action, then don't notify any event. (inner hanging up)
				if (pjsua_var[inst_id].calls[call_id].current_action == 2)
				{
					// reset call_hangup_request
					app_config[inst_id].call_hangup_request[call_id] = 0;

					tnl_event.event_code = NATNL_TNL_EVENT_HANGUP_OK;
					natnl_call_callback(&tnl_event);
				}
			}
		}
	}

	//pj_mutex_unlock(call->tnl_stream_lock4);
	//pj_mutex_unlock(call->tnl_stream_lock3);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 23"));
	pj_mutex_unlock(call->tnl_stream_lock2);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 24"));
	pj_mutex_unlock(call->tnl_stream_lock);
	PJ_LOG(4, (THIS_FILE, "on_call_media_destroy 25"));

}

static void re_reg_func(pj_timer_heap_t *th, struct pj_timer_entry *te)
{
	int *inst_id = (int *)te->user_data;
	//if (te->id == 1)
	//natnl_reg_device_with_inst_id(*inst_id);
	//pjsua_acc_set_registration(*inst_id, current_acc(*inst_id), PJ_TRUE);
	if (te == &app_config[*inst_id].one_day_reg_recovery_timer_entry)
		try_next_sip(*inst_id, PJ_TRUE);
	else
		try_next_sip(*inst_id, PJ_FALSE);
}

/*
 * Callback on media state changed event.
 * The action may connect the call to sound device, to file, or
 * to loop the call.
 */
static void on_call_media_state(pjsua_inst_id inst_id, pjsua_call_id call_id)
{

    PJ_LOG(4, (THIS_FILE, "[call flow] on_call_media_state() call_id=[%d].", call_id));

	pj_status_t status  = PJ_SUCCESS;
	pjsua_call *call = &pjsua_var[inst_id].calls[call_id];

    /* Stop ringback */
    //ring_stop(call_id);

    /* Connect ports appropriately when media status is ACTIVE or REMOTE HOLD,
     * otherwise we should NOT connect the ports.
     */
    PJ_LOG(4, (THIS_FILE, "[call flow] on_call_media_state() \tmedia_status=[%d].", 
               call->media_st));
    if (call->media_st == PJSUA_CALL_MEDIA_ACTIVE ||
        call->media_st == PJSUA_CALL_MEDIA_REMOTE_HOLD)
	{
		// do nothing
	}
}

//DEAN added
void on_media_channel_init(pjsua_inst_id inst_id, pjsua_call_id call_id, 
						   pjsip_role_e role)
{
#if defined(PJMEDIA_HAS_SRTP) && (PJMEDIA_HAS_SRTP != 0)
	struct transport_srtp *tp_srtp = (struct transport_srtp *)pjsua_var.calls[call_id].med_tp;
	struct pjmedia_transport *tp = 
		(struct pjmedia_transport *)pjmedia_transport_srtp_get_member((pjmedia_transport *)tp_srtp);
	if (!app_config[inst_id].media_cfg.enable_ice)
		return;
#elif defined(PJMEDIA_HAS_DTLS) && (PJMEDIA_HAS_DTLS != 0)
	#if defined(PJMEDIA_DISABLE_SCTP) && (PJMEDIA_DISABLE_SCTP != 0) // sctp disabled
		struct pjmedia_transport *tp_dtls =(struct pjmedia_transport *)pjsua_var[inst_id].calls[call_id].med_tp;
		struct pjmedia_transport *tp = 
			(struct pjmedia_transport *)pjmedia_transport_dtls_get_member((pjmedia_transport *)tp_dtls);
	#else
		struct pjmedia_transport *tp_sctp = (struct pjmedia_transport *)pjsua_var[inst_id].calls[call_id].med_tp;
		struct pjmedia_transport *tp_dtls = 
			(struct pjmedia_transport *)pjmedia_transport_sctp_get_member((pjmedia_transport *)tp_sctp);
		struct pjmedia_transport *tp = 
			(struct pjmedia_transport *)pjmedia_transport_dtls_get_member((pjmedia_transport *)tp_dtls);
	#endif
#else
	if (!app_config[inst_id].media_cfg.enable_ice)
		return;
	struct pjmedia_transport *tp = (struct pjmedia_transport *)pjsua_var[inst_id].calls[call_id].med_tp;

	struct transport_ice *tp_ice = (struct transport_ice *)tp;
#endif
	pj_str_t reg_call_id;

#if UPNP_PORT_MAPPING == 1
	tp->use_upnp_flag = app_config[inst_id].use_upnp_flag;
	tp->use_stun_cand = app_config[inst_id].use_stun_cand;
	tp->use_turn_flag = app_config[inst_id].use_turn_flag;
#endif
#if defined(PJMEDIA_DISABLE_SCTP) && (PJMEDIA_DISABLE_SCTP != 0) // sctp disabled
	((struct pjmedia_transport *)tp_dtls)->use_sctp = pjsua_var[inst_id].calls[call_id].use_sctp; // dean for WebRTC internal test.
#else
	((struct pjmedia_transport *)tp_dtls)->use_sctp = pjsua_var[inst_id].calls[call_id].use_sctp; // dean for WebRTC internal test.
	((struct pjmedia_transport *)tp_sctp)->use_sctp = pjsua_var[inst_id].calls[call_id].use_sctp; // dean for WebRTC internal test.
#endif

	/*if (role == PJSIP_ROLE_UAS && app_config[inst_id].nat_type == PJ_STUN_NAT_TYPE_OPEN)
	{
		tp->use_stun_cand = 0;
		tp->use_turn_flag = 0;
		PJ_LOG(3, (THIS_FILE, "on_media_channel_init() Its UAS and NAT type is OPEN. Don't add stun and turn candidate."));
	}*/

	reg_call_id.ptr = app_config[inst_id].reg_call_id;
	reg_call_id.slen = strlen(app_config[inst_id].reg_call_id);
	pjmedia_ice_set_turn_password(tp, reg_call_id);
	//set device id to entpoint for sdp encoding.
	pjmedia_transport_set_local_userid(tp, app_config[inst_id].user_id, strlen(app_config[inst_id].user_id));
	pjmedia_transport_set_local_deviceid(tp, 
		app_config[inst_id].natnl_cfg.device_id, sizeof(app_config[inst_id].natnl_cfg.device_id)); // INST_TODO
	// DEAN save turn server
	pjmedia_transport_set_local_turnsrv(tp, 
		app_config[inst_id].media_cfg.turn_server.ptr, 
		app_config[inst_id].media_cfg.turn_server.slen);
	pjmedia_transport_set_local_turnpwd(tp, 
		app_config[inst_id].reg_call_id, strlen(app_config[inst_id].reg_call_id));
	pjmedia_transport_set_local_nattype(tp, 
		app_config[inst_id].nat_type_name, strlen(app_config[inst_id].nat_type_name));
}

static int get_tnl_info(
	int call_id,
	struct natnl_tnl_info *tnl_info,
	int inst_id,
	int status_code) {
		pjsua_call *call = &pjsua_var[inst_id].calls[call_id];
		int status = (call->last_code == PJ_SUCCESS || status_code != PJ_SUCCESS) ? status_code : call->last_code;
		char *state, *ua_type, *tnl_type;

		if (inst_id <= 0 || inst_id > get_max_instances() || 
			call_id < 0 || call_id >= app_config[inst_id].natnl_cfg.max_calls ||
			!tnl_info)
			return PJ_EINVAL;

		if (!pjsua_var[inst_id].mutex) {
			status = NATNL_SC_NOT_INITED;
			goto on_return;
		}

		memset(tnl_info, 0, sizeof(struct natnl_tnl_info));

		if (status != PJ_SUCCESS &&
			status != PJ_SC_OK) {
			tnl_info->state = TNL_STATE_INACTIVE;
			tnl_info->status_code = (natnl_status_code)status;
			tnl_info->call_id = call_id;
			tnl_info->inst_id = inst_id;
			//goto on_return;
		} else {
			// state
			if (call->inv && (call->media_st == PJSUA_CALL_MEDIA_ACTIVE && 
				call->inv->state != PJSIP_INV_STATE_DISCONNECTED))
				tnl_info->state = TNL_STATE_ACTIVE;
			else
				tnl_info->state = TNL_STATE_INACTIVE;
			tnl_info->status_code = (natnl_status_code)call->last_code; 
			tnl_info->call_id = call->index;
			tnl_info->inst_id = call->inst_id;
			tnl_info->tnl_type = call->med_tp ? call->med_tp->tunnel_type : 0;
			tnl_info->tnl_build_spent_sec = call->tnl_build_spent_sec;

			if (call->last_text.slen > 0 && call->last_text.ptr) {
				my_memcpy(tnl_info->status_text, call->last_text.ptr, 
					sizeof(tnl_info->status_text), call->last_text.slen);
			}
		}

		tnl_info->ua_type = call->inv ? call->inv->role+1 : 0;

		//if (call->inv && call->inv->dlg)
		//	pjsip_dlg_inc_lock(call->inv->dlg); // lock dlg

		// session_id
		if (call->inv && call->inv->dlg->call_id->id.slen > 0 && call->inv->dlg->call_id->id.ptr) {
			my_memcpy(tnl_info->session_id, call->inv->dlg->call_id->id.ptr, 
				sizeof(tnl_info->session_id), call->inv->dlg->call_id->id.slen);
		}

		// local device_id
		if (call->inv && call->inv->dlg->local.info_str.slen > 0 && call->inv->dlg->local.info_str.ptr) {
			int str_slen = call->inv->dlg->local.info_str.slen+1;
			char *str_ptr = call->inv->dlg->local.info_str.ptr;
			char *device_id = (char *)malloc(str_slen);
			char *tmp;
			snprintf(device_id, str_slen, "%s", str_ptr);

			tmp = get_id_part_device_id(device_id);

			if (tmp)
				my_memcpy(tnl_info->para.local_info.device_id, tmp, 
				sizeof(tnl_info->para.local_info.device_id), strlen(tmp));
			free(device_id);
		}

		// remote device_id
		if (call->inv && call->inv->dlg->remote.info_str.slen > 0 && call->inv->dlg->remote.info_str.ptr) {
			int str_slen = call->inv->dlg->remote.info_str.slen+1;
			char *str_ptr = call->inv->dlg->remote.info_str.ptr;
			char *device_id = (char *)malloc(str_slen);
			char *tmp;
			snprintf(device_id, str_slen, "%s", str_ptr);

			tmp = get_id_part_device_id(device_id);

			if (tmp)
				my_memcpy(tnl_info->para.remote_info.device_id, tmp, 
				sizeof(tnl_info->para.remote_info.device_id), strlen(tmp));
			free(device_id);
		}

		// remote SDK version
		if (call->inv && call->inv->dlg->remote.ua_str.slen > 0 && call->inv->dlg->remote.ua_str.ptr) {
			my_memcpy(tnl_info->para.remote_info.version, call->inv->dlg->remote.ua_str.ptr, 
				sizeof(tnl_info->para.remote_info.version), call->inv->dlg->remote.ua_str.slen);
		}

		//if (call->inv && call->inv->dlg)
		//	pjsip_dlg_dec_lock(call->inv->dlg); // unlock dlg

		// local SDK version
		if (pjsua_var[inst_id].ua_cfg.user_agent.slen > 0 && pjsua_var[inst_id].ua_cfg.user_agent.ptr) {
			my_memcpy(tnl_info->para.local_info.version, pjsua_var[inst_id].ua_cfg.user_agent.ptr, 
				sizeof(tnl_info->para.local_info.version), pjsua_var[inst_id].ua_cfg.user_agent.slen);
		}

		// app_data
		tnl_info->app_data = app_config[inst_id].app_data;

		// TURN mapped address
		if (call->turn_mapped_addr)
			pj_sockaddr_print(call->turn_mapped_addr, tnl_info->turn_mapped_address, sizeof(tnl_info->turn_mapped_address), 3);

		// Modify status_code if any.
		if (tnl_info->status_code == PJ_SC_SERVICE_UNAVAILABLE && 
			pj_strcmp2(&call->last_text, "Operation timed out (PJ_ETIMEDOUT)") == 0) {
				tnl_info->status_code = NATNL_SC_CONNECT_TO_SIP_TIMEOUT;
		}

		// tunnel port pair information.
		{
			int i, j = 0;
			struct call_data *cd = (struct call_data *)pjsip_get_call_data(inst_id, call_id);
			int tnl_port_cnt = (tnl_info->state == TNL_STATE_ACTIVE) ? (cd->sock_servs ? cd->sock_servs->num_objs : 0) : 0;
			socket_t *tcp_serv = NULL;
			//pj_memset(tnl_info->tnl_ports, 0, sizeof(tnl_info->tnl_ports));

			tnl_info->tnl_port_cnt = tnl_port_cnt/2;
			PJ_LOG(4, (THIS_FILE, "get_tnl_info() tnl_port_cnt=[%d].", tnl_info->tnl_port_cnt));
			for (i=0; i < tnl_port_cnt; i+=2) {
				tcp_serv = (socket_t *)natnl_list_get_at(cd->sock_servs, i);
				sprintf(tnl_info->tnl_ports[j].lport, "%d", tcp_serv->lport);
				sprintf(tnl_info->tnl_ports[j].rport, "%d", tcp_serv->rport);
				tnl_info->tnl_ports[j].qos_priority = tcp_serv->qos_priority;
				tnl_info->tnl_ports[j].disable_flow_control = tcp_serv->disable_flow_control;
				tnl_info->tnl_ports[j].speed_limit = tcp_serv->speed_limit;
				sprintf(tnl_info->tnl_ports[j].rip, "%s", tcp_serv->rip);
				PJ_LOG(4, (THIS_FILE, "get_tnl_info() tnl_ports[%d]={%s, %s, %d, %d, %d, %s}.", 
					j, 
					tnl_info->tnl_ports[j].lport, 
					tnl_info->tnl_ports[j].rport,
					tnl_info->tnl_ports[j].qos_priority,
					tnl_info->tnl_ports[j].disable_flow_control,
					tnl_info->tnl_ports[j].speed_limit,
					tnl_info->tnl_ports[j].rip));
				j++;
			}
		}

		if (call->med_tp) {
			// Retry count
			tnl_info->retry_count.ice = call->med_tp->ice_retry_count;
			tnl_info->retry_count.dtls = call->med_tp->dtls_retry_count;
			tnl_info->retry_count.udt = call->med_tp->udt_retry_count;
			tnl_info->retry_count.sctp = call->med_tp->sctp_retry_count;
			tnl_info->stun_last_status = call->med_tp->stun_last_status;
			pj_strerror(tnl_info->stun_last_status, tnl_info->stun_status_text, sizeof(tnl_info->stun_status_text));
			tnl_info->turn_last_status = call->med_tp->turn_last_status;
			pj_strerror(tnl_info->turn_last_status, tnl_info->turn_status_text, sizeof(tnl_info->turn_status_text));
		}

		if (strlen(tnl_info->status_text) == 0) {
			pj_strerror(tnl_info->status_code, tnl_info->status_text, sizeof(tnl_info->status_text));
		}

on_return:

		status = PJ_SUCCESS;

		if (tnl_info->state == TNL_STATE_UNKNOWN)
			state = "UNKNOWN";
		else if (tnl_info->state == TNL_STATE_INACTIVE)
			state = "INACTIVE";
		else if (tnl_info->state == TNL_STATE_ACTIVE)
			state = "ACTIVE";
		else
			state = "UNKOWN";

		strncpy(tnl_info->state_text, state, strlen(state));

		if (tnl_info->ua_type == 0)
			ua_type = "UNKNOWN";
		else if (tnl_info->ua_type == 1)
			ua_type = "UAC";
		else if (tnl_info->ua_type == 2)
			ua_type = "UAS";
		else
			ua_type = "UNKOWN";

		if (tnl_info->tnl_type == 0)
			tnl_type = "UNKNOWN";
		else if (tnl_info->tnl_type == 1)
			tnl_type = "TCP";
		else if (tnl_info->tnl_type == 2)
			tnl_type = "TURN";
		else if (tnl_info->tnl_type == 3)
			tnl_type = "UDP";
		else
			tnl_type = "UNKOWN";

		PJ_LOG(4, (THIS_FILE, " \n >>>>>>>>>get_tnl_info \n >>inst_id=%d, \n >>call_id=%d, "
			"\n >>state=%d, \n >>state_text=%s, \n >>status_code=%d, \n >>status_text=%s, "
			"\n >>ua_type=%s, \n >>tnl_type=%s, \n >>session_id=%s, \n >>local_device_id=%s, "
			"\n >>local_sdk_version=%s, \n >>remote_device_id=%s, \n >>remote_sdk_varesion=%s, "
			"\n >>app_data=%p, \n >>turn_mapped_addr=%s, \n >>ice_retry=%d, \n >>dtls_retry=%d, "
			"\n >>udt_retry=%d, \n >>sctp_retry=%d, \n >>stun_last_status=%d, \n >>stun_status_text=%s, "
			"\n >>turn_last_status=%d, \n >>turn_status_text=%s, \n >>tnl_build_spent_sec=%d, "
			"\n get_tnl_info <<<<<<<<<", 
			tnl_info->inst_id,
			tnl_info->call_id,
			tnl_info->state,
			tnl_info->state_text,
			tnl_info->status_code,
			tnl_info->status_text,
			ua_type,
			tnl_type,
			tnl_info->session_id,
			tnl_info->para.local_info.device_id,
			tnl_info->para.local_info.version,
			tnl_info->para.remote_info.device_id,
			tnl_info->para.remote_info.version,
			tnl_info->app_data,
			tnl_info->turn_mapped_address,
			tnl_info->retry_count.ice,
			tnl_info->retry_count.dtls,
			tnl_info->retry_count.udt,
			tnl_info->retry_count.sctp,
			tnl_info->stun_last_status,
			tnl_info->stun_status_text,
			tnl_info->turn_last_status,
			tnl_info->turn_status_text,
			tnl_info->tnl_build_spent_sec));
		return status;
}

void on_tunnel_complete(pjsua_call *call, pj_status_t status)
{
#if defined(PJMEDIA_HAS_SRTP) && (PJMEDIA_HAS_SRTP != 0)
	struct transport_srtp *tp_srtp = (struct transport_srtp *)call->med_tp;
	struct pjmedia_transport *tp = 
		(struct pjmedia_transport *)pjmedia_transport_srtp_get_member((pjmedia_transport *)tp_srtp);
#elif defined(PJMEDIA_HAS_DTLS) && (PJMEDIA_HAS_DTLS != 0)
	#if defined(PJMEDIA_DISABLE_SCTP) && (PJMEDIA_DISABLE_SCTP != 0) // sctp disabled
		struct pjmedia_transport *tp_dtls = (struct pjmedia_transport *)call->med_tp;
		struct pjmedia_transport *tp = 
			(struct pjmedia_transport *)pjmedia_transport_dtls_get_member((pjmedia_transport *)tp_dtls);
	#else
		struct pjmedia_transport *tp_sctp = (struct pjmedia_transport *)call->med_tp;
		struct pjmedia_transport *tp_dtls = 
			(struct pjmedia_transport *)pjmedia_transport_sctp_get_member((pjmedia_transport *)tp_sctp);
		struct pjmedia_transport *tp = 
			(struct pjmedia_transport *)pjmedia_transport_dtls_get_member((pjmedia_transport *)tp_dtls);
	#endif
#else
	struct pjmedia_transport *tp = (struct pjmedia_transport *)call->med_tp;
#endif
	int inst_id = call->inst_id;
	int call_id = call->index;
	natnl_tunnel_type tnl_type = call->med_tp->tunnel_type;
	struct natnl_data *user_data = (struct natnl_data *)&app_config[inst_id].call_user_data[call_id];

	// Calculate total spent time.
	pj_time_val now;
	pj_gettimeofday(&now);
	PJ_TIME_VAL_SUB(now, call->start_time);
	call->tnl_build_spent_sec = now.sec;

on_return:
	struct natnl_tnl_info tnl_info;

	if (app_config[inst_id].call_data[call_id].timer.id != PJSUA_INVALID_ID) {
		struct call_data *cd = &app_config[inst_id].call_data[call_id];
		pjsip_endpoint *endpt = pjsua_get_pjsip_endpt(inst_id);

		cd->timer.id = PJSUA_INVALID_ID;
		pjsip_endpt_cancel_timer(endpt, &cd->timer);

		PJ_LOG(4, (THIS_FILE, "making call timeout check timer cancelled."));
	}

	PJ_LOG(1, (THIS_FILE, "on_tunnel_complete() ice_retry=[%d], dtls_retry=[%d], udt_retry=[%d], sctp_retry=[%d]", 
		call->med_tp->ice_retry_count,
		call->med_tp->dtls_retry_count,
		call->med_tp->udt_retry_count,
		call->med_tp->sctp_retry_count));

	if (status != PJ_SUCCESS && status != PJ_SC_OK) {
		pjsua_var[inst_id].calls[call_id].media_st = PJSUA_CALL_MEDIA_ERROR;
		pjsua_var[inst_id].calls[call_id].user_last_code = status;
	}

	// Print tunnel information.
	if (call->inv && call->inv->role == PJSIP_ROLE_UAS)
		get_tnl_info(call_id, &tnl_info, inst_id, status);

	// prepare natnl_data and post semaphore
	if (user_data && user_data->waiting_sem) {
		user_data->status = status;
		pj_sem_post(user_data->waiting_sem);
	}
	
	// DEAN call callback
	if (natnl_callback.on_natnl_tnl_event) {
		struct natnl_tnl_event tnl_event;
		memset(&tnl_event, 0, sizeof(tnl_event));
		tnl_event.inst_id = inst_id;
		if (tnl_event.inst_id >= 1)
			tnl_event.app_data = app_config[tnl_event.inst_id].app_data;
		tnl_event.call_id = call_id;

		tnl_event.ua_type = call->inv ? call->inv->role+1 : 0;
		tnl_event.nat_type = app_config[inst_id].nat_type;
		tnl_event.tnl_type = call->med_tp->tunnel_type;

		tnl_event.retry_count.ice = call->med_tp->ice_retry_count;
		tnl_event.retry_count.dtls = call->med_tp->dtls_retry_count;
		tnl_event.retry_count.udt = call->med_tp->udt_retry_count;
		tnl_event.retry_count.sctp = call->med_tp->sctp_retry_count;
		tnl_event.stun_last_status = call->med_tp->stun_last_status;
		pj_strerror(tnl_event.stun_last_status, tnl_event.stun_status_text, sizeof(tnl_event.stun_status_text));
		tnl_event.turn_last_status = call->med_tp->turn_last_status;
		pj_strerror(tnl_event.turn_last_status, tnl_event.turn_status_text, sizeof(tnl_event.turn_status_text));
		tnl_event.tnl_build_spent_sec = call->tnl_build_spent_sec;

		if (tp)
		{
			char tmp[64];
			memset(tmp, 0, sizeof(tmp));
			pjmedia_transport_get_remote_userid(tp, tmp);

			my_memcpy(tnl_event.para.remote_info.user_id, tmp, 
				sizeof(tnl_event.para.remote_info.user_id), strlen(tmp));
		}

		// device_id
		if (tp)
		{
			char full_device_id[128];
			char *device_id;
			memset(full_device_id, 0, 128);
			if (tnl_event.ua_type == 1) // UAC
			{
				if (tp->dest_uri)
				{
					pj_str_t *dest_uri = tp->dest_uri;
					strncpy(full_device_id, dest_uri->ptr, dest_uri->slen);
				}
			}
			else // UAS
			{
				pjmedia_transport_get_remote_deviceid(tp, full_device_id);
			}
			device_id = get_id_part_device_id(full_device_id);
			if (device_id)
				my_memcpy(tnl_event.para.remote_info.device_id, device_id, 
				sizeof(tnl_event.para.remote_info.device_id), strlen(device_id));
		}

		// dean prepare turn_mapped_address if any.
		if (pj_sockaddr_has_addr(&call->med_tp->turn_mapped_addr)) {
			pj_sockaddr_print(&call->med_tp->turn_mapped_addr, tnl_event.turn_mapped_address, 
				sizeof(tnl_event.turn_mapped_address), 3);
		} else {
			pj_memset(tnl_event.turn_mapped_address, 0, sizeof(tnl_event.turn_mapped_address));
		}

		//if (call->inv && call->inv->dlg)
		//	pjsip_dlg_inc_lock(call->inv->dlg); // lock dlg

		if (call->inv && call->inv->dlg->call_id->id.slen > 0 && call->inv->dlg->call_id->id.ptr) {
			my_memcpy(tnl_event.session_id, call->inv->dlg->call_id->id.ptr, 
				sizeof(tnl_event.session_id), call->inv->dlg->call_id->id.slen);
		}

		// DEAN Added 2013-03-15
		if (call->inv && call->inv->dlg->remote.ua_str.slen > 0 && call->inv->dlg->remote.ua_str.ptr) {
			my_memcpy(tnl_event.para.remote_info.version, call->inv->dlg->remote.ua_str.ptr, 
				sizeof(tnl_event.para.remote_info.version), call->inv->dlg->remote.ua_str.slen);
		}

		//if (call->inv && call->inv->dlg)
		//	pjsip_dlg_dec_lock(call->inv->dlg); // lock dlg

		// DEAN Added 2013-03-15
		if (pjsua_var[inst_id].ua_cfg.user_agent.slen > 0 && pjsua_var[inst_id].ua_cfg.user_agent.ptr) {
			my_memcpy(tnl_event.para.local_info.version, pjsua_var[inst_id].ua_cfg.user_agent.ptr, 
				sizeof(tnl_event.para.local_info.version), pjsua_var[inst_id].ua_cfg.user_agent.slen);
		}

		if (status == PJ_SUCCESS || status == PJ_SC_OK) {
			pj_str_t state_text = call->inv ? pj_str((char*)pjsip_inv_state_name(call->inv->state)) : pj_str("");

			if (tnl_type == NATNL_TUNNEL_TYPE_UNKNOWN)
				PJ_LOG(4, (__FILE__, "tunnel type=UNKNOWN"));
			else if (tnl_type == NATNL_TUNNEL_TYPE_UPNP_TCP)
				PJ_LOG(4, (__FILE__, "tunnel type=TCP"));
			else if (tnl_type == NATNL_TUNNEL_TYPE_TURN)
				PJ_LOG(4, (__FILE__, "tunnel type=TURN"));
			else if (tnl_type == NATNL_TUNNEL_TYPE_UDP)
				PJ_LOG(4, (__FILE__, "tunnel type=UDP"));

			if (tnl_event.ua_type == 0)
				PJ_LOG(4, (__FILE__, "ua type=UNKNOWN"));
			else if (tnl_event.ua_type == 1)
				PJ_LOG(4, (__FILE__, "ua type=UAC"));
			else if (tnl_event.ua_type == 2)
				PJ_LOG(4, (__FILE__, "ua type=UAS"));
			tnl_event.event_code = NATNL_TNL_EVENT_MAKECALL_OK;
			tnl_event.status_code = (natnl_status_code)call->last_code;
			if (call->last_text.slen > 0 && call->last_text.ptr) {
				my_memcpy(tnl_event.status_text, call->last_text.ptr, 
					sizeof(tnl_event.status_text), call->last_text.slen);
			}
			if (state_text.slen > 0 && state_text.ptr) {
				my_memcpy(tnl_event.event_text, state_text.ptr, 
					sizeof(tnl_event.event_text), state_text.slen);
			}

			// 2013-05-29 DEAN, if it's ip changing re-making call mode, don't notify event.
			natnl_call_callback(&tnl_event);
			pjsua_var[inst_id].calls[call_id].current_action = 2; // make ok
		} else {
			tnl_event.event_code = NATNL_TNL_EVENT_MAKECALL_FAILED;

			tnl_event.status_code = (natnl_status_code)status;

			// 2013-10-24 DEAN, if status is upper layer error then do hangup call.
			//if (tnl_event.status_code == NATNL_SC_TNL_CREATE_LIST_FAILED ||
			//	tnl_event.status_code == NATNL_SC_TNL_CREATE_SOCK_FAILED)
			pjsua_var[inst_id].calls[call_id].current_action = 1; // make call failed	

			// 2013-05-29 DEAN, if it's ip changing re-making call mode, don't notify event.
			natnl_call_callback(&tnl_event);
		}
	}

	if (status != PJ_SUCCESS && status != PJ_SC_OK)
		pjsua_call_hangup(inst_id, call_id, status, NULL, NULL);		
}

void on_ice_complete(pjsua_inst_id inst_id, pjsua_call_id call_id, 
					 pj_status_t status, pj_sockaddr *turn_mapped_addr)
{
#if defined(PJMEDIA_HAS_SRTP) && (PJMEDIA_HAS_SRTP != 0)
	struct transport_srtp *tp_srtp = (struct transport_srtp *)pjsua_var[inst_id].calls[call_id].med_tp;
	struct pjmedia_transport *tp = 
		(struct pjmedia_transport *)pjmedia_transport_srtp_get_member((pjmedia_transport *)tp_srtp);
#elif defined(PJMEDIA_HAS_DTLS) && (PJMEDIA_HAS_DTLS != 0)
	#if defined(PJMEDIA_DISABLE_SCTP) && (PJMEDIA_DISABLE_SCTP != 0) // sctp disabled
		struct pjmedia_transport *tp_dtls = pjsua_var[inst_id].calls[call_id].med_tp;
		struct pjmedia_transport *tp = 
			(struct pjmedia_transport *)pjmedia_transport_dtls_get_member((pjmedia_transport *)tp_dtls);
	#else
		struct pjmedia_transport *tp_sctp = pjsua_var[inst_id].calls[call_id].med_tp;
		struct pjmedia_transport *tp_dtls = 
			(struct pjmedia_transport *)pjmedia_transport_sctp_get_member((pjmedia_transport *)tp_sctp);
		struct pjmedia_transport *tp = 
			(struct pjmedia_transport *)pjmedia_transport_dtls_get_member((pjmedia_transport *)tp_dtls);
	#endif
#else
	struct pjmedia_transport *tp = (struct pjmedia_transport *)pjsua_var[inst_id].calls[call_id].med_tp;
#endif

	pjsua_call *call = &pjsua_var[inst_id].calls[call_id];
#if defined(PJMEDIA_DISABLE_SCTP) && (PJMEDIA_DISABLE_SCTP != 0) // sctp disabled
	tp_dtls->tunnel_type = tp->tunnel_type;
	tp_dtls->ice_retry_count = tp->ice_retry_count;
	tp_dtls->dtls_retry_count = tp->dtls_retry_count;
	tp_dtls->udt_retry_count = tp->udt_retry_count;
	tp_dtls->stun_last_status = tp->stun_last_status;
	tp_dtls->stun_last_status = tp->stun_last_status;
#else
	tp_dtls->tunnel_type = tp_sctp->tunnel_type = tp->tunnel_type;
	tp_sctp->ice_retry_count = tp->ice_retry_count;
	tp_sctp->dtls_retry_count = tp_dtls->dtls_retry_count;
	tp_sctp->udt_retry_count = tp->udt_retry_count;
	tp_dtls->stun_last_status = tp_sctp->stun_last_status = tp->stun_last_status;
	tp_dtls->turn_last_status = tp_sctp->turn_last_status = tp->turn_last_status;
	//tp_sctp->sctp_retry_count = tp->sctp_retry_count;
#endif

	pj_memset(&call->med_tp->turn_mapped_addr, 0, sizeof(call->med_tp->turn_mapped_addr));
	if (turn_mapped_addr && pj_sockaddr_has_addr(turn_mapped_addr))
		pj_sockaddr_cp(&call->med_tp->turn_mapped_addr, turn_mapped_addr);
	//pjsip_hdr *hdr, *end_hdr;


	if (app_config[inst_id].media_cfg.enable_ice)
		call->local_path_selected = pjmedia_ice_get_local_path_selected(tp);

	if (call->inv)
		PJ_LOG(4, (__FILE__, "on_ice_complete(). state=[%d]", call->inv->state));

	if (status != PJ_SUCCESS) {
		PJ_LOG(1, (__FILE__, "on_ice_complete() negotiate failed. status=[%d]", status));
		on_tunnel_complete(call, status);
		return;
	} else {
		PJ_LOG(4, (__FILE__, "on_ice_complete(). status=[%d]", status));

		// Save the the current sip for making call successfully for future use.
		app_config[inst_id].curr_sip_idx = app_config[inst_id].curr_re_inv_sip_idx[call_id];

		// Check if there is pending hanging up. If true hangup call immediately.
		if (app_config[inst_id].call_hangup_request[call_id] == 1) {
			PJ_LOG(4, (__FILE__, "on_ice_complete(). there is pending hangup. Hangup call immediately inst_id=[%d], call_id=[%d]", 
				inst_id, call_id));
			pjsua_call_hangup(inst_id, call_id, status, NULL, NULL);
			return;
		}
	}

	status = tunnel_init(inst_id, call_id, app_config[inst_id].natnl_cfg.bandwidth_KBs_limit);
	if (status != PJ_SUCCESS) 
	{
		PJ_LOG(2, (__FILE__, "on_ice_complete() Unable to init tunnel. "
			"status=[%d]", status));
		on_tunnel_complete(call, status);
		return;
	}

	if (!pjsua_var[inst_id].calls[call_id].tnl_stream->recv_thread) {
			if (status == PJ_SUCCESS) {
				pjsua_var[inst_id].calls[call_id].tnl_stream->thread_quit_flag = 0;
				pjsua_var[inst_id].calls[call_id].tnl_stream->tnl_type = tp->tunnel_type;
				status = pj_thread_create(pjsua_var[inst_id].calls[call_id].tnl_stream->pool, "natnl_recv_thread", &natnl_recv_thread,  
										  (void *)&pjsua_var[inst_id].calls[call_id], 0, 0,
										  &pjsua_var[inst_id].calls[call_id].tnl_stream->recv_thread);
				if (status != PJ_SUCCESS) 
				{
					PJ_LOG(2, (__FILE__, "on_ice_complete() Unable to create thread. "
						"status=[%d]", status));
					on_tunnel_complete(call, status);
					return;
				}
		}
	 }
}

void pjmedia_codec_ntc_deinit_cb(pjsua_inst_id inst_id) {
	// deinit ntc codec
	pjmedia_codec_ntc_deinit(inst_id);
}

int init(int argc, char *argv[], int inst_id) {

	unsigned int i;
	pjsua_transport_id transport_id = -1;
	pj_status_t status;
	pjsua_transport_config tcp_cfg;
	pjsua_transport_config tls_cfg;
	char *ch;

	struct natnl_data *user_data = NULL; // for synchronized API

	//app_config[inst_id].natnl_cfg.log_cfg.log_level = 0;

	// set log setting of instance 0
	app_config[0].log_cfg.level = app_config[inst_id].natnl_cfg.log_cfg.log_level; // DEAN modified
	app_config[0].log_cfg.console_level = app_config[inst_id].natnl_cfg.log_cfg.log_level;
	app_config[0].log_cfg.log_file_flags = app_config[inst_id].natnl_cfg.log_cfg.log_file_flags;
	app_config[0].log_cfg.log_file_size = app_config[inst_id].natnl_cfg.log_cfg.log_file_size;
	app_config[0].log_cfg.log_rotate_number = app_config[inst_id].natnl_cfg.log_cfg.log_rotate_number;
	app_config[0].log_cfg.facility = app_config[inst_id].natnl_cfg.log_cfg.syslog_facility;
	if (strlen(app_config[inst_id].natnl_cfg.log_cfg.log_filename) > 0)
		app_config[0].log_cfg.log_filename = pj_str(app_config[inst_id].natnl_cfg.log_cfg.log_filename);
	if (strlen(app_config[inst_id].natnl_cfg.log_cfg.log_flag_file) > 0)
		app_config[0].log_cfg.log_flag_file = pj_str(app_config[inst_id].natnl_cfg.log_cfg.log_flag_file);
	app_config[0].log_cfg.disable_console_log = app_config[inst_id].natnl_cfg.log_cfg.disable_console_log; // DEAN modified

	status = natnl_logging_endpt_create(0, 
		&app_config[0].log_cfg);
	if (status != PJ_SUCCESS)
		return status;

	// if there is already instance then enable append log.
	if (curr_instances == 1)
	{
		app_config[0].log_cfg.log_file_flags |= PJ_O_APPEND;
		status = pjsua_reconfigure_logging(0, &app_config[0].log_cfg);
		if (status != PJ_SUCCESS)
			return status;
	}

	/* Create natnl */
	status = natnl_create(inst_id);
	if (status != PJ_SUCCESS)
		return status;

	// prepare user_data for waiting make call result
	user_data = (struct natnl_data *)malloc(sizeof(struct natnl_data));
	user_data->user_data = NULL;

	status = pj_sem_create(pjsip_get_app_pool(inst_id), "init_sem" ,0, 1, &user_data->waiting_sem);
	if (status != PJ_SUCCESS)
		return status;
	app_config[inst_id].user_data = (void *)user_data;

	for (i = 0; i < app_config[inst_id].natnl_cfg.sip_srv_cnt; i++) //INST_TODO
	{
		// prepare tls sip-srv parameter
		// If sip port is 5061 or 443, it stands for tls transport is used.
		if ((ch = strstr(app_config[inst_id].natnl_cfg.sip_srv[i], ":5061")) || 
			(ch = strstr(app_config[inst_id].natnl_cfg.sip_srv[i], ":443"))) {
			pj_str_t dest = pj_str(app_config[inst_id].natnl_cfg.sip_srv[i]);
			pj_strcat2(&dest, ";transport=tls");
			//printf(app_config[inst_id].natnl_cfg.sip_srv[i]);		
		}
		if (i == 0 && (ch = strstr(app_config[inst_id].natnl_cfg.sip_srv[i], ";transport=tls"))) {
			app_config[inst_id].natnl_cfg.use_tls = 1;
		}
	}

	app_config[inst_id].curr_sip_idx = 0;
	app_config[inst_id].sip_retry_cnt = 1;

	sprintf(app_config[inst_id].registrar_uri_str, "sip:%s", app_config[inst_id].natnl_cfg.sip_srv[0]);
	PJ_LOG(4, (THIS_FILE, "1**************************"));

	PJ_LOG(4, (THIS_FILE, "2**************************"));
#if defined(PJ_WIN32_UWP)
	pjsua_var[0].log_cfg.cb = &log_cb;
#endif

	/* Initialize default config */
	default_app_config(inst_id, &app_config[inst_id]); 

	// DEAN. Show date on logs.
	app_config[inst_id].log_cfg.decor = app_config[inst_id].log_cfg.decor | 
		                                PJ_LOG_HAS_YEAR | PJ_LOG_HAS_MONTH | PJ_LOG_HAS_DAY_OF_MON |
										PJ_LOG_HAS_LEVEL_TEXT;

	/* Configure the config based on config-file */
	config_app_config(inst_id, &app_config[inst_id]);

	// save user ports to pjsua_var.calls
	if (app_config[inst_id].natnl_cfg.upnp_cfg.flag == 2) {
		for (i=0; i<app_config[inst_id].natnl_cfg.upnp_cfg.user_port_count; ++i) {
			pjsua_var[inst_id].calls[i].user_port_assigned = PJ_FALSE;

			if (i < pjsua_var[inst_id].ua_cfg.max_calls) {
				pjsua_var[inst_id].calls[i].local_tcp_data_port = 
					atoi(app_config[inst_id].natnl_cfg.upnp_cfg.user_ports[i].local_data);

				pjsua_var[inst_id].calls[i].external_tcp_data_port = 
					atoi(app_config[inst_id].natnl_cfg.upnp_cfg.user_ports[i].external_data);

				pjsua_var[inst_id].calls[i].local_tcp_ctl_port = 
					atoi(app_config[inst_id].natnl_cfg.upnp_cfg.user_ports[i].local_ctl);

				pjsua_var[inst_id].calls[i].external_tcp_ctl_port = 
					atoi(app_config[inst_id].natnl_cfg.upnp_cfg.user_ports[i].external_ctl);

				pjsua_var[inst_id].calls[i].user_port_assigned = PJ_TRUE;
			}
		}
	}

	// save tunnel timeout value
	if (app_config[inst_id].natnl_cfg.tnl_timeout_sec > (MAX_TNL_TIMEOUT_SEC - 10))
		pjsua_var[inst_id].tnl_timeout_msec = (MAX_TNL_TIMEOUT_SEC - 10) * 1000;
	else
		pjsua_var[inst_id].tnl_timeout_msec = app_config[inst_id].natnl_cfg.tnl_timeout_sec * 1000;

	// save idle timeout value
	if (app_config[inst_id].natnl_cfg.idle_timeout_sec < 0)
		pjsua_var[inst_id].idle_timeout_msec = 0;
	else
		pjsua_var[inst_id].idle_timeout_msec = app_config[inst_id].natnl_cfg.idle_timeout_sec * 1000;

	// init re-register timer entry
	pj_timer_entry_init(&app_config[inst_id].re_reg_timer_entry, 0, 
		(void*)&pjsua_var[inst_id].id, &re_reg_func);
	// init one day re-register timer entry
	pj_timer_entry_init(&app_config[inst_id].one_day_reg_recovery_timer_entry, 0, 
		(void*)&pjsua_var[inst_id].id, &re_reg_func);
	//app_config[inst_id].is_one_day_reg_recovery_timer_scheduled = PJ_FALSE;
	
	PJ_LOG(4, (THIS_FILE, "3**************************"));
    /* Initialize application callbacks */
    app_config[inst_id].cfg.cb.on_nat_detect_natnl = &on_nat_detect; //DEAN modified
    app_config[inst_id].cfg.cb.on_reg_state = &on_reg_state;
    app_config[inst_id].cfg.cb.on_reg_state2 = &on_reg_state2;
    app_config[inst_id].cfg.cb.on_transport_state = &on_transport_state;
    app_config[inst_id].cfg.cb.on_call_state = &on_call_state;
    app_config[inst_id].cfg.cb.on_incoming_call = &on_incoming_call;
    app_config[inst_id].cfg.cb.on_call_media_state = &on_call_media_state;
    app_config[inst_id].cfg.cb.on_call_media_destroy = &on_call_media_destroy;
    app_config[inst_id].cfg.cb.on_call_tsx_state = &on_call_tsx_state;
    //app_config[inst_id].cfg.cb.on_ice_transport_error = &on_ice_transport_error;// DEAN no needed anymore.
    app_config[inst_id].cfg.cb.on_media_channel_init = &on_media_channel_init; //DEAN added
	app_config[inst_id].cfg.cb.on_ice_complete = &on_ice_complete; // natnl
	app_config[inst_id].cfg.cb.pjmedia_codec_ntc_deinit_cb = &pjmedia_codec_ntc_deinit_cb;
	app_config[inst_id].cfg.cb.on_stun_binding_complete = &on_stun_binding_complete;
	app_config[inst_id].cfg.cb.on_pager2 = &on_pager2;
	app_config[inst_id].cfg.cb.on_pager_status2 = &on_pager_status2;

#ifdef TODO
    app_config[inst_id].cfg.cb.on_dtmf_digit = &call_on_dtmf_callback;
    app_config[inst_id].cfg.cb.on_call_redirected = &call_on_redirected;
    app_config[inst_id].cfg.cb.on_incoming_subscribe = &on_incoming_subscribe;
    app_config[inst_id].cfg.cb.on_buddy_state = &on_buddy_state;
    app_config[inst_id].cfg.cb.on_buddy_evsub_state = &on_buddy_evsub_state;
    app_config[inst_id].cfg.cb.on_pager = &on_pager;
    app_config[inst_id].cfg.cb.on_typing = &on_typing;
    app_config[inst_id].cfg.cb.on_call_transfer_status = &on_call_transfer_status;
    app_config[inst_id].cfg.cb.on_call_replaced = &on_call_replaced;
    app_config[inst_id].cfg.cb.on_mwi_info = &on_mwi_info;
    app_config[inst_id].log_cfg.cb = log_cb;
#endif

	PJ_LOG(4, (THIS_FILE, "4**************************"));
    /* Initialize natnl */
    status = natnl_init(inst_id,
						&app_config[inst_id].cfg, 
						&app_config[inst_id].log_cfg, 
						&app_config[inst_id].media_cfg);
    if (status != PJ_SUCCESS)
		return status;
	
	// Print SDK version.
	PJ_LOG(3, (THIS_FILE, "ASUS NAT Tunnel Library Version : [%s]", NATNL_LIB_VERSION));

	PJ_LOG(4, (THIS_FILE, "@param@ log_level=[%d]", app_config[inst_id].natnl_cfg.log_cfg.log_level));
	PJ_LOG(4, (THIS_FILE, "@param@ log_filename=[%s]", app_config[inst_id].natnl_cfg.log_cfg.log_filename));
	PJ_LOG(4, (THIS_FILE, "@param@ log_file_flags=[%d]", app_config[inst_id].natnl_cfg.log_cfg.log_file_flags));
	PJ_LOG(4, (THIS_FILE, "@param@ log_file_size=[%d]", app_config[inst_id].natnl_cfg.log_cfg.log_file_size));
	PJ_LOG(4, (THIS_FILE, "@param@ log_rotate_number=[%d]", app_config[inst_id].natnl_cfg.log_cfg.log_rotate_number));
	PJ_LOG(4, (THIS_FILE, "@param@ log_flag_file=[%s]", app_config[inst_id].natnl_cfg.log_cfg.log_flag_file));
	PJ_LOG(4, (THIS_FILE, "@param@ syslog_facility=[%d]", app_config[inst_id].natnl_cfg.log_cfg.syslog_facility));
	PJ_LOG(4, (THIS_FILE, "@param@ disable_console_log=[%d]", app_config[inst_id].natnl_cfg.log_cfg.disable_console_log));
	PJ_LOG(4, (THIS_FILE, "@param@ device-id=[%s]", app_config[inst_id].natnl_cfg.device_id));
	PJ_LOG(4, (THIS_FILE, "@param@ device-pwd=[%s]", app_config[inst_id].natnl_cfg.device_pwd));
	PJ_LOG(4, (THIS_FILE, "@param@ sip-srv-cnt=[%d]", app_config[inst_id].natnl_cfg.sip_srv_cnt));
	for (i = 0; i < app_config[inst_id].natnl_cfg.sip_srv_cnt; i++)
		PJ_LOG(4, (THIS_FILE, "@param@ sip-srv[%d]=[%s]", i, app_config[inst_id].natnl_cfg.sip_srv[i]));
	PJ_LOG(4, (THIS_FILE, "@param@ max-calls=[%d]", app_config[inst_id].natnl_cfg.max_calls));
	PJ_LOG(4, (THIS_FILE, "@param@ use-tls=[%d]", app_config[inst_id].natnl_cfg.use_tls));
	PJ_LOG(4, (THIS_FILE, "@param@ verify-server=[%d]", app_config[inst_id].natnl_cfg.verify_server));
	PJ_LOG(4, (THIS_FILE, "@param@ use-stun=[%d]", app_config[inst_id].natnl_cfg.use_stun));
	PJ_LOG(4, (THIS_FILE, "@param@ stun-srv-cnt=[%d]", app_config[inst_id].natnl_cfg.stun_srv_cnt));
	for (i = 0; i < app_config[inst_id].natnl_cfg.stun_srv_cnt; i++)
		PJ_LOG(4, (THIS_FILE, "@param@ stun-srv[%d]=[%s]", i, app_config[inst_id].natnl_cfg.stun_srv[i]));
	PJ_LOG(4, (THIS_FILE, "@param@ use-turn=%d", app_config[inst_id].natnl_cfg.use_turn));
	PJ_LOG(4, (THIS_FILE, "@param@ turn-srv-cnt=[%d]", app_config[inst_id].natnl_cfg.turn_srv_cnt));
	for (i = 0; i < app_config[inst_id].natnl_cfg.turn_srv_cnt; i++)
		PJ_LOG(4, (THIS_FILE, "@param@ turn-srv[%d]=[%s]", i, app_config[inst_id].natnl_cfg.turn_srv[i]));
	PJ_LOG(4, (THIS_FILE, "@param@ use-upnp=[%d]", app_config[inst_id].natnl_cfg.upnp_cfg.flag));
	PJ_LOG(4, (THIS_FILE, "@param@ tnl_timeout_sec=[%d]", app_config[inst_id].natnl_cfg.tnl_timeout_sec));
	PJ_LOG(4, (THIS_FILE, "@param@ disable_sdp_compress=[%d]", app_config[inst_id].natnl_cfg.disable_sdp_compress));
	PJ_LOG(4, (THIS_FILE, "@param@ bandwidth_KBs_limit=[%d]", app_config[inst_id].natnl_cfg.bandwidth_KBs_limit));
	PJ_LOG(4, (THIS_FILE, "@param@ is_server_side_app=[%d]", app_config[inst_id].natnl_cfg.is_server_side_app));
	PJ_LOG(4, (THIS_FILE, "@param@ idle_timeout_sec=[%d]", app_config[inst_id].natnl_cfg.idle_timeout_sec));
	PJ_LOG(4, (THIS_FILE, "@param@ fast_init=[%d]", app_config[inst_id].natnl_cfg.fast_init));
	PJ_LOG(4, (THIS_FILE, "@param@ enable_secure_data=[%d]", app_config[inst_id].natnl_cfg.enable_secure_data));
	PJ_LOG(4, (THIS_FILE, "@param@ cert=[%s]", app_config[inst_id].natnl_cfg.cert));
	PJ_LOG(4, (THIS_FILE, "@param@ cert_pkey=[%s]", app_config[inst_id].natnl_cfg.cert_pkey));
	PJ_LOG(4, (THIS_FILE, "@param@ trusted_ca_certs=[%s]", app_config[inst_id].natnl_cfg.trusted_ca_certs));
	PJ_LOG(4, (THIS_FILE, "@param@ verify_server_peer=[%d]", app_config[inst_id].natnl_cfg.verify_server_peer));
	PJ_LOG(4, (THIS_FILE, "@param@ use_sctp=[%d]", app_config[inst_id].natnl_cfg.use_sctp));
	PJ_LOG(4, (THIS_FILE, "@param@ im_port_count=[%d]", app_config[inst_id].natnl_cfg.im_port_count));
	for (i = 0; i < app_config[inst_id].natnl_cfg.im_port_count; i++)
		PJ_LOG(4, (THIS_FILE, "@param@ im_ports[%d]={%s, %s, %s, %d}", i, app_config[inst_id].natnl_cfg.im_ports[i].dest_device_id, 
															app_config[inst_id].natnl_cfg.im_ports[i].lport, 
															app_config[inst_id].natnl_cfg.im_ports[i].rport, 
															app_config[inst_id].natnl_cfg.im_ports[i].timeout_sec));
	PJ_LOG(4, (THIS_FILE, "@param@ sip_trusted_ca_certs=[%s]", app_config[inst_id].natnl_cfg.sip_trusted_ca_certs));
	PJ_LOG(4, (THIS_FILE, "@param@ sip_verify_server_peer=[%d]", app_config[inst_id].natnl_cfg.sip_verify_server_peer));

	if (!app_config[inst_id].natnl_cfg.fast_init) 
	{
		/* Perform NAT detection */
		status = pjsua_detect_nat_type(inst_id);
		//if (status != PJ_SUCCESS)  //DEAN. Ignore stun failed situation to meet UDP packet blocked environment.
		//	return status;
	}

	mod_default_handler_initialize();

	PJ_LOG(4, (THIS_FILE, "5**************************"));
    /* Initialize our module to handle otherwise unhandled request */
    status = pjsip_endpt_register_module(pjsua_get_pjsip_endpt(inst_id), &mod_default_handler[inst_id]);
    if (status != PJ_SUCCESS)
		return status;

    /* Initialize calls data */
    for (i=0; i<PJ_ARRAY_SIZE(app_config[inst_id].call_data); ++i) {
        app_config[inst_id].call_data[i].timer.id = PJSUA_INVALID_ID;
        app_config[inst_id].call_data[i].timer.cb = &call_timeout_callback;
	}
	PJ_LOG(4, (THIS_FILE, "6**************************"));

	pj_memcpy(&tcp_cfg, &app_config[inst_id].udp_cfg, sizeof(tcp_cfg));
	pj_memcpy(&tls_cfg, &app_config[inst_id].udp_cfg, sizeof(tls_cfg));

#ifdef COLLECT_TCP_CAND
	// DEAN modified 
	// We will do this when NAT type detected completely.
	// 2014-01-17 Move to here before SIP Registration.
	if (app_config[inst_id].natnl_cfg.upnp_cfg.flag == 1 &&
		!app_config[inst_id].natnl_cfg.fast_init)
		InitUpnp(&app_config[inst_id].upnp); // Discover UPnP
#endif

	app_config[inst_id].rtp_cfg.auto_del = PJ_TRUE; // DEAN. if call terminated, destroy media transport automatically.
	
	/* Copy media transport config */
	pjsua_transport_config_dup(pjsua_var[inst_id].pool, &pjsua_var[inst_id].rtp_cfg, &app_config[inst_id].rtp_cfg);
#if 0 // DEAN. No need to create media transport on initialization stage.
	if (app_config[inst_id].natnl_cfg.is_server_side_app) {
		/* Add RTP transports */
		// 2014-01-17 Move to here before SIP Registration.

		if (app_config[inst_id].ipv6)
			status = create_ipv6_media_transports(inst_id);
		else
			status = pjsua_media_transports_create(inst_id, &app_config[inst_id].rtp_cfg);

		if (status != PJ_SUCCESS)
			goto on_error;
	}
#endif
    /* Add UDP transport unless it's disabled. */
	PJ_LOG(4, (THIS_FILE, "7**************************app_config.no_udp=[%d]", 
		app_config[inst_id].no_udp));

    if (!app_config[inst_id].no_udp) {
        pjsua_acc_id aid;
        pjsip_transport_type_e type = PJSIP_TRANSPORT_UDP;

        status = pjsua_transport_create(inst_id, type, &app_config[inst_id].udp_cfg, &transport_id);
        if (status != PJ_SUCCESS)
            goto on_return;

        /* Add local account */
        pjsua_acc_add_local(inst_id, transport_id, PJ_TRUE, &aid);
        pjsua_acc_set_online_status(inst_id, current_acc(inst_id), PJ_TRUE);

        if (app_config[inst_id].udp_cfg.port == 0) {
            pjsua_transport_info ti;
            pj_sockaddr_in *a;

            pjsua_transport_get_info(inst_id, transport_id, &ti);
            a = (pj_sockaddr_in*)&ti.local_addr;

            tcp_cfg.port = pj_ntohs(a->sin_port);
        }
    }

	PJ_LOG(4, (THIS_FILE, "8**************************app_config[inst_id].no_tcp=[%d]", 
	   app_config[inst_id].no_tcp));
    /* Add TCP transport unless it's disabled */
    if (!app_config[inst_id].no_tcp) {
        status = pjsua_transport_create(inst_id, PJSIP_TRANSPORT_TCP, &tcp_cfg, &transport_id);
        if (status != PJ_SUCCESS)
            goto on_return;

        /* Add local account */
        pjsua_acc_add_local(inst_id, transport_id, PJ_TRUE, NULL);
        pjsua_acc_set_online_status(inst_id, current_acc(inst_id), PJ_TRUE);

	}

	// 2013-05-15 DEAN force to create tls transport.
#if defined(PJSIP_HAS_TLS_TRANSPORT) && PJSIP_HAS_TLS_TRANSPORT!=0
	/* Add TLS transport when application wants one */

	pjsua_acc_id acc_id;

	/* Copy the QoS settings */
	tls_cfg.tls_setting.qos_type = tls_cfg.qos_type;
	pj_memcpy(&tls_cfg.tls_setting.qos_params, &tls_cfg.qos_params, 
		sizeof(tls_cfg.qos_params));

	/*if (strlen(app_config[inst_id].natnl_cfg.sip_trusted_ca_certs))
		tls_cfg.tls_setting.ca_list_file = pj_str(app_config[inst_id].natnl_cfg.sip_trusted_ca_certs);
	
	tls_cfg.tls_setting.verify_server = app_config[inst_id].natnl_cfg.sip_verify_server_peer;*/

	/* Set TLS port as TCP port+1 */
	tls_cfg.port = tcp_cfg.port+1;
	status = pjsua_transport_create(inst_id, PJSIP_TRANSPORT_TLS,
		&tls_cfg, 
		&transport_id);
	//tls_cfg.port--;
	if (status != PJ_SUCCESS)
		goto on_return;

	/* Add local account */
	pjsua_acc_add_local(inst_id, transport_id, PJ_FALSE, &acc_id);
	pjsua_acc_set_online_status(inst_id, acc_id, PJ_TRUE);
#endif

	PJ_LOG(4, (THIS_FILE, "10**************************"));
    if (transport_id == -1) {
        PJ_LOG(1, (THIS_FILE, "Error: no transport is configured"));
        status = -1;
        goto on_return;
    }

	PJ_LOG(4, (THIS_FILE, "11**************************"));
	/* Add accounts */
	for (i=0; i<app_config[inst_id].acc_cnt; ++i) {
		app_config[inst_id].acc_cfg[i].reg_retry_interval = 0; //DEAN. Retry registration by ourself.
		app_config[inst_id].acc_cfg[i].reg_first_retry_interval = 60;

		status = pjsua_acc_add(inst_id, &app_config[inst_id].acc_cfg[i], PJ_TRUE, NULL);
		if (status != PJ_SUCCESS)
			goto on_return;
		pjsua_acc_set_online_status(inst_id, current_acc(inst_id), !app_config[inst_id].natnl_cfg.fast_init);
	}

	PJ_LOG(4, (THIS_FILE, "12**************************"));
	/* Add buddies */
	for (i=0; i<app_config[inst_id].buddy_cnt; ++i) {
		status = pjsua_buddy_add(inst_id, &app_config[inst_id].buddy_cfg[i], NULL);
		if (status != PJ_SUCCESS)
			goto on_return;
	}
	PJ_LOG(4, (THIS_FILE, "13**************************"));

    if (status != PJ_SUCCESS)
        goto on_return;

	PJ_LOG(4, (THIS_FILE, "15**************************"));

	if (!app_config[inst_id].natnl_cfg.fast_init) {
		// waiting for initializing result.
		pj_sem_wait(user_data->waiting_sem);
		status = user_data->status == 200 ? 0 : user_data->status;
	}

on_return:
	if (user_data) {
		if (user_data->waiting_sem) {
			pj_sem_destroy(user_data->waiting_sem);
			user_data->waiting_sem = NULL;
		}
		free(user_data);
		user_data = NULL;

		app_config[inst_id].user_data = NULL;
	}

	return status;
}

#ifdef NATNL_LIB

NATNL_LIB_API void WINAPI natnl_dump_version_with_inst_id(int argc, char *argv[], int inst_id) {
	pj_thread_desc desc;
	pj_thread_t *thread;

	pj_thread_register(inst_id, "natnl_dump_version_with_inst_id", desc, &thread);

	int c;
	int option_index;
	enum {OPT_VERSION = 505};
	struct pj_getopt_option long_options[] = {
		{ "version", 2, 0, OPT_VERSION}
	};
	pj_optind = 2;
	c=pj_getopt_long(argc, argv, "", long_options,&option_index);
	if (c == OPT_VERSION) {
		printVersion();
	}
}
NATNL_LIB_API void WINAPI natnl_dump_version(int argc, char *argv[]) {
	natnl_dump_version_with_inst_id(argc, argv, 1);
}

NATNL_LIB_API int WINAPI natnl_pool_dump_with_inst_id(int detail, int inst_id) {
	pj_thread_desc desc;
	pj_thread_t *thread;

	if (inst_id <= 0 || inst_id > get_max_instances())
		return PJ_EINVAL;

	pj_thread_register(inst_id, "natnl_pool_dump_with_inst_id", desc, &thread);

    pjsua_dump(inst_id, detail);

    return PJ_SUCCESS;
}

NATNL_LIB_API int WINAPI natnl_pool_dump(int detail) {
	return natnl_pool_dump_with_inst_id(detail, 1);
}

NATNL_LIB_API int WINAPI natnl_set_max_instances(int max_instances) {
	if (max_instances < 1) 
		return -1;

	if (max_instances > (PJSUA_MAX_INSTANCES-2))
		return -2;
	
	set_max_instances(max_instances+1);
	return 0;
}

NATNL_LIB_API int WINAPI natnl_lib_init_with_inst_id3(struct natnl_config *cfg, 
				int *inst_id, 
				struct natnl_callback *natnl_cb, 
				void *app_data) {
	int status;

#if defined(PJ_WIN32) && !defined(PJ_WIN32_UWP)
	// Set signal handler for crash stack trace use.
	set_signal_handler();
#endif

#ifdef PJ_LINUX
	//setup_action_signal();
#endif
#if defined(PJ_DARWINOS) // To prevent broken pipe signal
	setup_socket_signal();
#endif

	//if (natnl_inited) {

	*inst_id = 1;
	if (get_max_instances() > 2) {
		*inst_id = alloc_inst_id();

		if (*inst_id == PJSUA_INVALID_ID) { 
			status = NATNL_SC_TOO_MANY_INSTANCES;
			goto on_return;
		}
	}

	if (app_config[*inst_id].is_initializing) {
		status = NATNL_SC_INITIALIZING;
		goto on_return;
	}

	// INST_TODO
	if (pjsua_var[*inst_id].mutex) { 
		status = NATNL_SC_ALREADY_INITED;
		goto on_return;
	}

	app_config[*inst_id].is_initializing = PJ_TRUE;

	cfg->disable_sdp_compress = 1;
	cfg->bandwidth_KBs_limit = 0;

#ifndef SW_HW_AUTH
#if defined(ROUTER) && !defined(BLUECAVE)
	#if defined(MAPAC1300) || defined(MAPAC2200) || defined(VZWAC1300) || defined(RTAC95U) // Using iwpriv on map-ac1300 and map-ac2200 and vzw-ac1300
	{
		char *cmd1 = "iwpriv wifi0 get_txpwrpc";
		//char *cmd2 = "iwpriv2 wifi0 get_txpwrpc";
		//char *cmd3 = "iwpriv wifi0 get_txpwrpc1";
		int ret;
		int rand_v;
		ret = system(cmd1);
		/*printf("cmd1 ret=%d\n", ret);
		ret = system(cmd2);
		printf("cmd2 ret=%d\n", ret);
		ret = system(cmd3);
		printf("cmd3 ret=%d\n", ret);*/
		if (ret != 0) {
			srand (time(NULL));
			rand_v = rand() % 2;

			if (rand_v)
				goto on_return;
		} else {
			app_config[*inst_id].is_our_product = 1;
			//printf("clm_data_ver: %s\n", buf);
		}
	}
	#else
	{
#ifndef BLUECAVE
#ifdef HND_ROUTER
#define        WIF     "eth6"
#else
#define        WIF     "eth1"
#endif
		int ret = 0;
		char buf[WLC_IOCTL_MEDLEN];
		uint wl_cmd = WLC_GET_VAR;
		memset(buf, 0, WLC_IOCTL_MEDLEN);

		//printf("%s\n", WIF);
		memcpy(buf, "clm_data_ver", strlen("clm_data_ver"));
		if (natnl_wl_ioctl(WIF, wl_cmd, buf, sizeof(buf))) {
			int rand_v;
			//printf("clm_data_ver: failed!!, ret=%d\n", ret);
			app_config[*inst_id].is_our_product = 0;
			srand (time(NULL));
			rand_v = rand() % 2;

			if (rand_v)
				goto on_return;
		} else {
			app_config[*inst_id].is_our_product = 1;
			//printf("clm_data_ver: %s\n", buf);
		}
#endif //BLUECAVE
	}
	#endif
#endif
#endif

	memcpy(&app_config[*inst_id].natnl_cfg, cfg, sizeof(app_config[*inst_id].natnl_cfg));
	if (natnl_cb)
		memcpy(&natnl_callback, natnl_cb, sizeof(struct natnl_callback));

	// TODO disable the feature first.
	//app_config[*inst_id].natnl_cfg.log_cfg.log_file_size = 0;
	//app_config[*inst_id].natnl_cfg.log_cfg.log_rotate_number = 0;
	//app_config[*inst_id].natnl_cfg.log_cfg.log_level = 4;

	app_config[*inst_id].app_data = app_data;

	app_config[*inst_id].register_only = PJ_FALSE; // DEAN, to determine initialization or register, un-register only

	status = init(0, NULL, *inst_id);
	if (status != PJ_SUCCESS) {
		// destroy pjsua if any.
		//pjsua_destroy(*inst_id);
		app_config[*inst_id].is_initializing = PJ_FALSE;

		// empty app_config if any.
		//pj_bzero(&app_config[*inst_id], sizeof(app_config[*inst_id]));

		deinit_lib(*inst_id);

		goto on_return;
	}

	// Add instant message port.
	if (app_config[*inst_id].natnl_cfg.im_port_count) {
		status = update_instant_msg_port(1, app_config[*inst_id].natnl_cfg.im_port_count, app_config[*inst_id].natnl_cfg.im_ports, *inst_id);
		if (status != PJ_SUCCESS) {
			app_config[*inst_id].is_initializing = PJ_FALSE;
			deinit_lib(*inst_id);
			goto on_return;
		}

		memcpy(cfg->im_ports, &app_config[*inst_id].natnl_cfg.im_ports, sizeof(cfg->im_ports));
	}

	// initial variables.
	app_config[*inst_id].is_deinitializing = PJ_FALSE;
	pj_get_timestamp(&app_config[*inst_id].last_ip_changed);

	curr_instances++; // regard return value, increment curr_instances anyway.

	app_config[*inst_id].is_initializing = PJ_FALSE;

	PJ_LOG(4, (THIS_FILE, "SDK initialization finished. status=[%d]", status)); 
#ifdef PJ_WIN32
	DBG("SDK initialization finished. status=[%d]", status);
#endif

on_return:
	return status;
}

NATNL_LIB_API int WINAPI natnl_lib_init_with_inst_id2(struct natnl_config *cfg, 
				int *inst_id,
				void *app_data) {
	return natnl_lib_init_with_inst_id3(cfg, inst_id, NULL, app_data);
}

NATNL_LIB_API int WINAPI natnl_lib_init_with_inst_id(struct natnl_config *cfg,
	int *inst_id) {
	return natnl_lib_init_with_inst_id3(cfg, inst_id, NULL, NULL);
}

NATNL_LIB_API int WINAPI natnl_lib_init(struct natnl_config *cfg) {
	int inst_id = 1;
	return natnl_lib_init_with_inst_id(cfg, &inst_id);
}

NATNL_LIB_API int WINAPI natnl_lib_init2(struct natnl_config *cfg,
	void *app_data) {
	int inst_id = 1;
	return natnl_lib_init_with_inst_id3(cfg, &inst_id, NULL, app_data);
}

NATNL_LIB_API int WINAPI natnl_lib_init3(struct natnl_config *cfg, 
							struct natnl_callback *natnl_cb,
							void *app_data) {
   int inst_id = 1;
   return natnl_lib_init_with_inst_id3(cfg, &inst_id, natnl_cb, app_data);
}

static int deinit_lib(int inst_id) {
	pj_status_t status = PJ_FALSE;

	pj_thread_desc desc;
	pj_thread_t *thread;

	PJ_LOG(4, (THIS_FILE, "deinit_lib(). inst_id=[%d]", inst_id));

	if (app_config[inst_id].is_deinitializing) {
		return NATNL_SC_DE_INITIALIZING;
	}

	app_config[inst_id].is_deinitializing = PJ_TRUE;

	im_destroy(inst_id);

	status = pjsua_destroy(inst_id);


	if (--curr_instances == 0) // regard return value, decrement curr_instances anyway.
		pjsua_destroy(0);

	if (app_config[inst_id].cfg.user_agent.ptr) {  // free memory
		free(app_config[inst_id].cfg.user_agent.ptr);
		app_config[inst_id].cfg.user_agent.ptr = NULL;
	}

	pj_bzero(&app_config[inst_id], sizeof(app_config[inst_id]));

	 // remove append flag if current number of instances is 1
	if (curr_instances == 1 
		&& app_config[0].natnl_cfg.log_cfg.log_file_flags != 1
		&& app_config[0].natnl_cfg.log_cfg.log_file_flags != PJ_O_APPEND)
	{
		app_config[0].log_cfg.log_file_flags &= ~PJ_O_APPEND;

		pjsua_reconfigure_logging(0, &app_config[0].log_cfg);
	}

	udt_cleanup();

	//usrsctp_finish();
#if !defined(PJMEDIA_DISABLE_SCTP) || (PJMEDIA_DISABLE_SCTP==0) // enable sctp
	shutdown_usrsctp();
#endif

	app_config[inst_id].is_deinitializing = PJ_FALSE;

	return status;
}

NATNL_LIB_API int WINAPI natnl_lib_deinit_with_inst_id(int inst_id) {
	pj_status_t status = PJ_FALSE;

	pj_thread_desc desc;
	pj_thread_t *thread;

	if (inst_id <= 0 || inst_id > get_max_instances())
		return PJ_EINVAL;

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	pj_thread_register(inst_id, "natnl_lib_deinit_with_inst_id", desc, &thread);

	PJ_LOG(4, (THIS_FILE, "natnl_lib_deinit(). inst_id=[%d]", inst_id));

	return deinit_lib(inst_id);
}

NATNL_LIB_API int WINAPI natnl_lib_deinit(void) {
	return natnl_lib_deinit_with_inst_id(1);
}

NATNL_LIB_API int WINAPI natnl_lib_deinit_all(void) {
	pj_status_t status = PJ_FALSE;

	pj_thread_desc desc;
	pj_thread_t *thread;

	int i;
	
	for (i=PJSUA_MAX_INSTANCES-1; i >= 0; i--)
	{
		if (i != 0 && !pjsua_var[i].mutex) {
			status = NATNL_SC_NOT_INITED;
			continue;
		}

		if (!pj_thread_is_registered(i))
			pj_thread_register(i, "natnl_lib_deinit_all", desc, &thread);
		status = PJ_FALSE;

		app_config[i].is_deinitializing = PJ_TRUE;

		im_destroy(i);

		status = pjsua_destroy(i);

		if (app_config[i].cfg.user_agent.ptr) {  // free memory
			free(app_config[i].cfg.user_agent.ptr);
			app_config[i].cfg.user_agent.ptr = NULL;
		}

		pj_bzero(&app_config[i], sizeof(app_config[i]));

		curr_instances--; // regard return value, decrement curr_instances anyway.
	}

	udt_cleanup();

	//usrsctp_finish();
#if !defined(PJMEDIA_DISABLE_SCTP) || (PJMEDIA_DISABLE_SCTP==0) // enable sctp
	shutdown_usrsctp();
#endif

	return status;
}

NATNL_LIB_API int WINAPI natnl_make_call_with_inst_id(char *device_id,
				int tnl_port_cnt, 
				natnl_tnl_port tnl_ports[], char *user_id,
				int timeout_sec, int use_sctp, int inst_id, struct natnl_tnl_info *tnl_info) {
	return natnl_make_call_with_inst_id2(device_id, tnl_port_cnt, tnl_ports,
		user_id, timeout_sec, use_sctp, inst_id, NULL, tnl_info);
}

NATNL_LIB_API int WINAPI natnl_make_call_with_inst_id2(char *device_id,
	int tnl_port_cnt, natnl_tnl_port tnl_ports[],char *user_id, 
	int timeout_sec, int use_sctp, int inst_id,
	char *caller_device_pwd, struct natnl_tnl_info *tnl_info) {

	pj_thread_desc desc;
	pj_thread_t *thread;

	int ret;
	int i;
	int call_id;
	char *buff = NULL;
	char uri_to_be_called[128];

	pjsua_msg_data msg_data;
	pj_str_t dest_uri;
	pj_status_t status;

	struct natnl_data *user_data = NULL;

	//natnl_data *user_data = NULL; // for synchronized API
	//natnl_tnl_info tnl_info;

	memset(tnl_info, 0, sizeof(struct natnl_tnl_info));

	if (inst_id <= 0 || inst_id > get_max_instances() || 
		tnl_port_cnt <= 0 || 
		tnl_port_cnt > MAX_TUNNEL_PORT_COUNT) {
			tnl_info->status_code = (natnl_status_code)PJ_EINVAL;
			strncpy(tnl_info->status_text ,"Invalid parameter.", sizeof(tnl_info->status_text));
		return PJ_EINVAL;
	}

	if (!pjsua_var[inst_id].mutex) {
		tnl_info->status_code = NATNL_SC_NOT_INITED;
		strncpy(tnl_info->status_text , "SDK isn't initialized, please initialize it first.", sizeof(tnl_info->status_text));
		return NATNL_SC_NOT_INITED;
	}

	if (app_config[inst_id].is_deinitializing) {
		tnl_info->status_code = NATNL_SC_DE_INITIALIZING;
		strncpy(tnl_info->status_text , "The SDK is de-initializing.", sizeof(tnl_info->status_text));
		return NATNL_SC_DE_INITIALIZING;
	}

	pj_thread_register(inst_id, "natnl_make_call_with_inst_id2", desc, &thread);

	PJ_LOG(4, (THIS_FILE, "natnl_make_call(). inst_id=[%d]", inst_id));

	// DEAN. Update caller device password if any.
	if (app_config[inst_id].natnl_cfg.fast_init && caller_device_pwd && strlen(caller_device_pwd))
	{
		PJ_LOG(4, (THIS_FILE, "natnl_make_call() Update caller device password (%s -> %s)", 
			app_config[inst_id].natnl_cfg.device_pwd, caller_device_pwd));

		memset(app_config[inst_id].natnl_cfg.device_pwd, 0, sizeof(app_config[inst_id].natnl_cfg.device_pwd));
		my_memcpy(app_config[inst_id].natnl_cfg.device_pwd, caller_device_pwd, 
			sizeof(app_config[inst_id].natnl_cfg.device_pwd), strlen(caller_device_pwd));

		reconfig_device_pwd(&app_config[inst_id], inst_id);

		/* Copy configuration */
		pjsua_media_config_dup(pjsua_var[inst_id].pool, &pjsua_var[inst_id].media_cfg, &app_config[inst_id].media_cfg);
	}

	app_config[inst_id].cfg.outbound_proxy[app_config[inst_id].cfg.outbound_proxy_cnt++] = pj_str("sip:aae-sgsip065-2.asus.com:5061");

	memset(uri_to_be_called, 0, sizeof(uri_to_be_called));
	buff = strstr(device_id, "@");
	if (buff && strlen(buff) > 1) { //with sip uri
		sprintf(uri_to_be_called, "sip:%s", 
			device_id);
	} else if (buff && strlen(buff) == 1) { //with '@'
		sprintf(uri_to_be_called, "sip:%s%s", 
			device_id, app_config[inst_id].natnl_cfg.sip_srv[app_config[inst_id].curr_sip_idx]);
	} else {
		sprintf(uri_to_be_called, "sip:%s@%s", 
			device_id, app_config[inst_id].natnl_cfg.sip_srv[app_config[inst_id].curr_sip_idx]);
	}
	dest_uri = pj_str(uri_to_be_called);
    pjsua_msg_data_init(&msg_data);

	pj_bzero(app_config[inst_id].user_id, sizeof(app_config[inst_id].user_id));
	strncpy(app_config[inst_id].user_id, user_id, strlen(user_id));

	// allocate a new call_id.
	call_id = alloc_call_id(inst_id);

	// prepare user_data for waiting make call result
	user_data = &app_config[inst_id].call_user_data[call_id];
	user_data->user_data = NULL;
	status = pj_sem_create(pjsip_get_app_pool(inst_id), "mk_sem" ,0, 1, &user_data->waiting_sem);
	if (status != PJ_SUCCESS)
	goto on_return;

	// Prepare re-invite timer first
	// init call_hangup_request to 0
	app_config[inst_id].call_hangup_request[call_id] = 0;

	// init re-invite timer entry
	app_config[inst_id].re_inv_info[call_id].inst_id = inst_id;
	app_config[inst_id].re_inv_info[call_id].call_id = call_id;
	memset(app_config[inst_id].re_inv_info[call_id].dest_uri, 0, sizeof(app_config[inst_id].re_inv_info[call_id].dest_uri));
	strncpy(app_config[inst_id].re_inv_info[call_id].dest_uri, uri_to_be_called, strlen(uri_to_be_called));
	app_config[inst_id].sip_re_inv_cnt[call_id] = 1;
	app_config[inst_id].curr_re_inv_sip_idx[call_id] = app_config[inst_id].curr_sip_idx;

#if defined(PJMEDIA_DISABLE_SCTP) && (PJMEDIA_DISABLE_SCTP!=0) // disable sctp
	use_sctp = 0;
#endif

	pj_timer_entry_init(&app_config[inst_id].re_inv_timer_entry[call_id], 0, 
						(void*)&app_config[inst_id].re_inv_info[call_id], &re_inv_func);
	PJ_LOG(4, (__FILE__, "natnl_make_call() init re-invite timer. inst_id=[%d], call_id=[%d], current_acc=[%d], tmp.str=[%s], user_id=[%d], timeout_sec=[%d], use_sctp=[%d], status=[%d]", 
		   inst_id, call_id, current_acc(inst_id), dest_uri.ptr, user_id, timeout_sec, use_sctp, status));
	status = pjsua_call_make_call( inst_id, current_acc(inst_id), &dest_uri, 0, use_sctp, user_id, &msg_data, &call_id);


	if (status == PJ_SUCCESS) {

		// init call_hangup_request to 0
		app_config[inst_id].call_hangup_request[call_id] = 0;

		// init re-invite timer entry
		app_config[inst_id].re_inv_info[call_id].inst_id = inst_id;
		app_config[inst_id].re_inv_info[call_id].call_id = call_id;
		memset(app_config[inst_id].re_inv_info[call_id].dest_uri, 0, sizeof(app_config[inst_id].re_inv_info[call_id].dest_uri));
		strncpy(app_config[inst_id].re_inv_info[call_id].dest_uri, uri_to_be_called, strlen(uri_to_be_called));
		app_config[inst_id].sip_re_inv_cnt[call_id] = 1;
		app_config[inst_id].curr_re_inv_sip_idx[call_id] = app_config[inst_id].curr_sip_idx;

		pj_timer_entry_init(&app_config[inst_id].re_inv_timer_entry[call_id], 0, 
			(void*)&app_config[inst_id].re_inv_info[call_id], &re_inv_func);
		PJ_LOG(4, (__FILE__, "natnl_make_call() init re-invite timer. inst_id=[%d], call_id=[%d], current_acc=[%d], tmp.str=[%s], user_id=[%d], timeout_sec=[%d], use_sctp=[%d], status=[%d]", 
			inst_id, call_id, current_acc(inst_id), dest_uri.ptr, user_id, timeout_sec, use_sctp, status));

		pjsua_var[inst_id].calls[call_id].current_action = 1; // for callback event
	}

	for (i = 0; i < tnl_port_cnt; i++)
	{
		PJ_LOG(4, (THIS_FILE, "natnl_make_call() call_id=[%d], tnl_ports[%d]=(%s, %s, %d, %d, %d, %s)", 
			call_id, i, tnl_ports[i].lport, tnl_ports[i].rport, 
			tnl_ports[i].qos_priority, tnl_ports[i].disable_flow_control, tnl_ports[i].speed_limit, tnl_ports[i].rip));
	}

	PJ_LOG(4, (__FILE__, "natnl_make_call() inst_id=[%d], call_id=[%d], current_acc=[%d], dest_uri.str=[%s], user_id=[%d], timeout_sec=[%d], use_sctp=[%d], status=[%d]", 
		inst_id, call_id, current_acc(inst_id), dest_uri.ptr, user_id, timeout_sec, use_sctp, status));

	if (status != PJ_SUCCESS)
		goto on_return;

	update_tunnel_port(inst_id, call_id, 1, tnl_port_cnt, tnl_ports, 1);

	app_config[inst_id].duration = (unsigned)timeout_sec;

	if (app_config[inst_id].duration != 0)
	{
		/* Schedule timer to hangup call after the specified duration */
		struct call_data *cd = &app_config[inst_id].call_data[call_id];
		pjsip_endpoint *endpt = pjsua_get_pjsip_endpt(inst_id);
		pj_time_val delay;

		cd->timer.id = call_id;
		cd->timer.user_data = &pjsua_var[inst_id].calls[call_id];
		delay.sec = app_config[inst_id].duration;
		delay.msec = 0;
		pjsip_endpt_cancel_timer(endpt, &cd->timer);
		pjsip_endpt_schedule_timer(endpt, &cd->timer, &delay);
	}

	// wait for making call result.
	pj_sem_wait(user_data->waiting_sem);
	status = user_data->status == 200 ? 0 : user_data->status;
	
on_return:
	get_tnl_info(call_id, tnl_info, inst_id, status);
	if (user_data) {
		if (user_data->waiting_sem) {
			pj_sem_destroy(user_data->waiting_sem);
			user_data->waiting_sem = NULL;
		}
	}
	return status;
}

NATNL_LIB_API int WINAPI natnl_make_call(char *device_id, int tnl_port_cnt, 
							natnl_tnl_port tnl_ports[],char *user_id, 
							int timeout_sec, int use_sctp, struct natnl_tnl_info *tnl_info) {
		return natnl_make_call_with_inst_id(device_id, tnl_port_cnt, 
			tnl_ports, user_id, timeout_sec, use_sctp, 1, tnl_info);
}

NATNL_LIB_API int WINAPI natnl_hangup_call_with_inst_id(int call_id, int inst_id) {
	pj_status_t status = PJ_SUCCESS;
	pj_thread_desc desc;
	pj_thread_t *thread;

	if (inst_id <= 0 || inst_id > get_max_instances())
		return PJ_EINVAL;

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	// Validate call_id
	if (call_id < 0 || call_id > (app_config[inst_id].natnl_cfg.max_calls-1)) {
		return PJ_EINVAL;
	}

	//if (!pj_thread_is_registered(inst_id))
		pj_thread_register(inst_id, "natnl_hangup_call_with_inst_id", desc, &thread);

	PJ_LOG(4, (THIS_FILE, "natnl_hangup_call(). inst_id=[%d], call_id=[%d]", inst_id, call_id));

	PJ_LOG(5, (THIS_FILE, "natnl_hangup_call()......2"));

	if(call_id != PJSUA_INVALID_ID)
		status = pjsua_call_hangup(inst_id, call_id, 0, NULL, NULL);

	if (status == PJ_SUCCESS)
		pjsua_var[inst_id].calls[call_id].current_action = 2; // for callback event

	app_config[inst_id].call_hangup_request[call_id] = 1;

	return status;
}

NATNL_LIB_API int WINAPI natnl_hangup_call(int call_id) {
	return natnl_hangup_call_with_inst_id(call_id, 1);
}

NATNL_LIB_API int WINAPI natnl_reg_device_with_inst_id(int inst_id) {
	pj_status_t status;
	pj_thread_desc desc;
	pj_thread_t *thread;

	struct natnl_data *user_data = NULL; // for synchronized API

	if (inst_id <= 0 || inst_id > get_max_instances())
		return PJ_EINVAL;

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	pj_thread_register(inst_id, "natnl_reg_device_with_inst_id", desc, &thread);

	PJ_LOG(4, (THIS_FILE, "natnl_reg_device(). inst_id=[%d]", inst_id));

	// wait for another registration finished, if any.
	if (app_config[inst_id].user_data) {
		if (((struct natnl_data *)app_config[inst_id].user_data)->waiting_sem) {
			status = PJ_EBUSY;
			goto on_return;
		}
	}

	// prepare user_data for waiting make call result
	user_data = (struct natnl_data *)malloc(sizeof(struct natnl_data));
	user_data->user_data = NULL;
	status = pj_sem_create(pjsip_get_app_pool(inst_id), "rd_sem" ,0, 1, &user_data->waiting_sem);
	if (status != PJ_SUCCESS)
		goto on_return;
	app_config[inst_id].user_data = (void *)user_data;

	app_config[inst_id].register_only = PJ_TRUE; // DEAN, to determine initialization or register, un-register only

	app_config[inst_id].is_app_invoking_reg = PJ_TRUE;
	status = pjsua_acc_set_registration(inst_id, current_acc(inst_id), PJ_TRUE);
	if (status != PJ_SUCCESS)
		goto on_return;

	// waiting for registration result.
	pj_sem_wait(user_data->waiting_sem);
	status = user_data->status == 200 ? 0 : user_data->status;

	app_config[inst_id].is_app_invoking_reg = PJ_FALSE;

on_return:
	if (user_data) {
		if (user_data->waiting_sem) {
			pj_sem_destroy(user_data->waiting_sem);
			user_data->waiting_sem = NULL;
		}
		free(user_data);
		user_data = NULL;

		app_config[inst_id].user_data = NULL;
	}

	return status;
}

NATNL_LIB_API int WINAPI natnl_reg_device(void) {
	return natnl_reg_device_with_inst_id(1);
}

NATNL_LIB_API int WINAPI natnl_unreg_device_with_inst_id(int inst_id) {
	pj_status_t status;
	pj_thread_desc desc;
	pj_thread_t *thread;

	struct natnl_data *user_data = NULL; // for synchronized API

	if (inst_id <= 0 || inst_id > get_max_instances())
		return PJ_EINVAL;

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	pj_thread_register(inst_id, "natnl_unreg_device_with_inst_id", desc, &thread);

	PJ_LOG(4, (THIS_FILE, "natnl_unreg_device(). inst_id=[%d]", inst_id));

	// wait for another registration finished, if any.
	if (app_config[inst_id].user_data) {
		if (((struct natnl_data *)app_config[inst_id].user_data)->waiting_sem) {
			status = PJ_EBUSY;
			goto on_return;
		}
	}

	// prepare user_data for waiting make call result
	user_data = (struct natnl_data *)malloc(sizeof(struct natnl_data));
	user_data->user_data = NULL;
	status = pj_sem_create(pjsip_get_app_pool(inst_id), "unrd_sem" ,0, 1, &user_data->waiting_sem);
	if (status != PJ_SUCCESS)
		goto on_return;
	app_config[inst_id].user_data = (void *)user_data;

	app_config[inst_id].register_only = PJ_TRUE; // DEAN, to determine initialization or register, un-register only

	status = pjsua_acc_set_registration(inst_id, current_acc(inst_id), PJ_FALSE);
	if (status != PJ_SUCCESS)
		goto on_return;

	// waiting for registration result.
	pj_sem_wait(user_data->waiting_sem);
	status = user_data->status == 200 ? 0 : user_data->status;

on_return:
	if (user_data) {
		if (user_data->waiting_sem) {
			pj_sem_destroy(user_data->waiting_sem);
			user_data->waiting_sem = NULL;
		}
		free(user_data);
		user_data = NULL;

		app_config[inst_id].user_data = NULL;
	}

	return status;
}

NATNL_LIB_API int WINAPI natnl_unreg_device(void) {
	return natnl_unreg_device_with_inst_id(1);
}

/* DEAN reconfig device_id */
static void reconfig_sip_srv(struct app_config *cfg, int inst_id)
{
	int i;
	pjsua_acc_config *cur_acc;

	PJ_LOG(4, (THIS_FILE, "reconfig_sip_srv(). inst_id=[%d]", inst_id));

	if (inst_id <= 0)
		return;

	for(i=0;i<ACCOUNT_CNT;i++) {
		cur_acc = &cfg->acc_cfg[i];

		//Registrar
		cur_acc->reg_uri = pj_str(app_config[inst_id].registrar_uri_str);
	}
}

/* DEAN reconfig device_id */
static void reconfig_device_id(struct app_config *cfg, int inst_id)
{
	int i;
	pjsua_acc_config *cur_acc;

	PJ_LOG(4, (THIS_FILE, "reconfig_device_id(). inst_id=[%d]", inst_id));

	if (inst_id <= 0)
		return;

	for(i=0;i<ACCOUNT_CNT;i++) {
		cur_acc = &cfg->acc_cfg[i];

		char tmp_device_id[128];

		strcpy(tmp_device_id, cfg->natnl_cfg.device_id);

		PJ_LOG(4, (THIS_FILE, "device_id=%s", tmp_device_id));

		char *tmp;
		tmp = strtok(tmp_device_id, "@");
		if (tmp)
			strcpy(app_config[inst_id].username, tmp);
		tmp = strtok(NULL, "@");
		if (tmp)
			strcpy(app_config[inst_id].realm, tmp);

		sprintf(app_config[inst_id].account_id, "sip:%s", cfg->natnl_cfg.device_id);

		//SIP account
		cur_acc->id = pj_str(app_config[inst_id].account_id);

		//Realm
		cur_acc->cred_info[i].realm = pj_str(app_config[inst_id].realm);

		//authentication Username
		cur_acc->cred_info[i].username = pj_str(app_config[inst_id].username);
	}
}

/* DEAN reconfig device_id */
static void reconfig_device_pwd(struct app_config *cfg, int inst_id)
{
	int i;
	pjsua_acc_config *cur_acc;

	for(i=0;i<ACCOUNT_CNT;i++) {
		cur_acc = &cfg->acc_cfg[i];

		//authentication Password
		cur_acc->cred_info[i].data = pj_str(cfg->natnl_cfg.device_pwd);
	}

	cfg->media_cfg.turn_auth_cred.data.static_cred.data = pj_str(cfg->natnl_cfg.device_pwd);

	/* Copy configuration */
	pjsua_media_config_dup(pjsua_var[inst_id].pool, &pjsua_var[inst_id].media_cfg, &cfg->media_cfg);
}

/* DEAN reconfig use_stun*/
static void reconfig_use_stun(struct app_config *cfg)
{
	cfg->use_stun_cand = cfg->natnl_cfg.use_stun;
}

/* DEAN reconfig use_turn*/
static void reconfig_use_turn(struct app_config *cfg)
{
	cfg->media_cfg.enable_turn = cfg->natnl_cfg.use_turn;
	cfg->use_turn_flag = cfg->natnl_cfg.use_turn;	

	if (!cfg->media_cfg.enable_turn)
		cfg->media_cfg.turn_server.slen = 0;
}

/* DEAN reconfig use_upnp*/
static void reconfig_use_upnp(struct app_config *cfg)
{
	cfg->use_upnp_flag = cfg->natnl_cfg.upnp_cfg.flag;
}

/* DEAN reconfig turn_srv */
static void reconfig_turn_srv(struct app_config *cfg, int inst_id)
{
	int i;

	char tmp_device_id[128];

	PJ_LOG(4, (THIS_FILE, "reconfig_turn_srv(). inst_id=[%d]", inst_id));

	if (inst_id <= 0)
		return;

	strcpy(tmp_device_id, cfg->natnl_cfg.device_id);

	PJ_LOG(4, (THIS_FILE, "device_id=%s", tmp_device_id));

	char *tmp;
	tmp = strtok(tmp_device_id, "@");
	if (tmp)
		strcpy(app_config[inst_id].username, tmp);
	tmp = strtok(NULL, "@");
	if (tmp)
		strcpy(app_config[inst_id].realm, tmp);

	if (cfg->media_cfg.enable_ice && 
		cfg->natnl_cfg.use_turn && 
		cfg->natnl_cfg.turn_srv_cnt)
		cfg->media_cfg.enable_turn = PJ_TRUE;

	if (cfg->media_cfg.enable_turn) {
		cfg->media_cfg.turn_server_cnt = cfg->natnl_cfg.turn_srv_cnt;
		
		for (i = 0; i < cfg->natnl_cfg.turn_srv_cnt; i++) {
			if (i == 0)
				cfg->media_cfg.turn_server = pj_str(cfg->natnl_cfg.turn_srv[i]);

			cfg->media_cfg.turn_server_list[i] = pj_str(cfg->natnl_cfg.turn_srv[i]);
		}
		
		cfg->media_cfg.turn_conn_type = PJ_TURN_TP_UDP;
		cfg->media_cfg.turn_auth_cred.type = PJ_STUN_AUTH_CRED_STATIC;
		cfg->media_cfg.turn_auth_cred.data.static_cred.realm = pj_str(app_config[inst_id].realm);
		cfg->media_cfg.turn_auth_cred.data.static_cred.username = pj_str(app_config[inst_id].username);

		cfg->media_cfg.turn_auth_cred.data.static_cred.data = pj_str(cfg->natnl_cfg.device_pwd);
		cfg->media_cfg.turn_auth_cred.data.static_cred.data_type = PJ_STUN_PASSWD_PLAIN;
	} else {
		cfg->media_cfg.turn_server.slen = 0;
	}
}

int check_and_update_config(struct natnl_config *cfg, int inst_id) {
	pj_status_t status = PJ_SUCCESS;
	pj_bool_t need_re_register = PJ_FALSE;
	pj_bool_t need_re_create_media_transport = PJ_FALSE;

	PJ_LOG(4, (THIS_FILE, "check_and_update_config(). inst_id=[%d]", inst_id));

	// log config
	if (app_config[inst_id].log_cfg.level != cfg->log_cfg.log_level ||
		app_config[inst_id].log_cfg.log_file_flags != cfg->log_cfg.log_file_flags ||
		pj_strcmp2(&app_config[inst_id].log_cfg.log_filename, cfg->log_cfg.log_filename) != 0) 
	{
		app_config[inst_id].log_cfg.level = cfg->log_cfg.log_level;
		app_config[inst_id].log_cfg.console_level = cfg->log_cfg.log_level;
		app_config[inst_id].log_cfg.log_file_flags = cfg->log_cfg.log_file_flags;
		app_config[inst_id].log_cfg.log_filename = pj_str(cfg->log_cfg.log_filename);

		status = pjsua_reconfigure_logging(inst_id, &app_config[inst_id].log_cfg);
		
		PJ_LOG(4, (THIS_FILE, "log_cfg reconfig. status=[%d], level=[%d]", status, pj_log_get_level(inst_id)));
	} 
	else
	{
		PJ_LOG(4, (THIS_FILE, "log_cfg doesn't be changed."));
	}

#ifdef ALLOW_UPDATE_SVR_CFG
	// sip server config
	for (i=0; i < cfg->sip_srv_cnt; i++) {
		// Check changed for sip_srv
		if (strlen(cfg->sip_srv[i]) > 0 &&
			strcmp(app_config[inst_id].natnl_cfg.sip_srv[i], cfg->sip_srv[i]) != 0) {
				strcpy(app_config[inst_id].natnl_cfg.sip_srv[i], cfg->sip_srv[i]);
				if (i == 0) {
					sprintf(registrar_uri_str, "sip:%s", app_config[inst_id].natnl_cfg.sip_srv[i]);
					reconfig_sip_srv(&app_config[inst_id], inst_id);
				}

				need_re_register = PJ_TRUE;
		}
	}

	// Check changed for device_id
	if (strlen(cfg->device_id) > 0 &&
		strcmp(app_config[inst_id].natnl_cfg.device_id, cfg->device_id) != 0) {
			strcpy(app_config[inst_id].natnl_cfg.device_id, cfg->device_id);
			reconfig_device_id(&app_config[inst_id], inst_id);

			need_re_register = PJ_TRUE;
	}

	// Check changed for device_pwd
	if (strlen(cfg->device_pwd) > 0 &&
		strcmp(app_config[inst_id].natnl_cfg.device_pwd, cfg->device_pwd) != 0) {
			strcpy(app_config[inst_id].natnl_cfg.device_pwd, cfg->device_pwd);
			reconfig_device_pwd(&app_config[inst_id], inst_id);

			need_re_register = PJ_TRUE;
	}

	// Check changed for use_stun
	if (app_config[inst_id].natnl_cfg.use_stun != cfg->use_stun) {
		app_config[inst_id].natnl_cfg.use_stun = cfg->use_stun;
		reconfig_use_stun(&app_config[inst_id]);
	}

	// Check changed for use_turn
	if (app_config[inst_id].natnl_cfg.use_turn != cfg->use_turn) {
		app_config[inst_id].natnl_cfg.use_turn = cfg->use_turn;
		reconfig_use_turn(&app_config[inst_id]);

		need_re_create_media_transport = PJ_TRUE;
	}

	// turn server config
	for (i=0; i < cfg->turn_srv_cnt; i++) {
		app_config[inst_id].natnl_cfg.turn_srv_cnt = cfg->turn_srv_cnt;
		// Check changed for turn_srv
		if (strlen(cfg->turn_srv[i]) > 0 &&
			strcmp(app_config[inst_id].natnl_cfg.turn_srv[i], cfg->turn_srv[i]) != 0) {
				strcpy(app_config[inst_id].natnl_cfg.turn_srv[i], cfg->turn_srv[i]);

				if (i == (cfg->turn_srv_cnt-1))
					reconfig_turn_srv(&app_config[inst_id]);

				need_re_create_media_transport = PJ_TRUE;
		}
	}

	// Check changed for use_upnp
	if (app_config[inst_id].natnl_cfg.upnp_cfg.flag != cfg->upnp_cfg.flag) {
		app_config[inst_id].natnl_cfg.upnp_cfg.flag = cfg->upnp_cfg.flag;
		reconfig_use_upnp(&app_config[inst_id]);
	}

	// Check if we need to re-registration to SIP Sever.
	if (need_re_register) {
		int i;
		for (i=0; i<app_config[inst_id].acc_cnt; ++i) {
			app_config[inst_id].acc_cfg[i].reg_retry_interval = 0; //DEAN. Retry registration by ourself.
			app_config[inst_id].acc_cfg[i].reg_first_retry_interval = 60;

			status = pjsua_acc_add(&app_config[inst_id].acc_cfg[i], PJ_TRUE, NULL);
			if (status != PJ_SUCCESS)
				return status;
			pjsua_acc_set_online_status(current_acc, PJ_TRUE);
		}

		register_only = PJ_TRUE; // DEAN, to determine initialization or register, un-register only

		status = pjsua_acc_set_registration(current_acc, PJ_TRUE);
	}

	// Check if we need to re-create media transport.
	if (need_re_create_media_transport) {

		/* Copy configuration */
		pjsua_media_config_dup(pjsua_var.pool, &pjsua_var.media_cfg, &app_config[inst_id].media_cfg);

		/* Add RTP transports */
		if (app_config[inst_id].ipv6)
			status = create_ipv6_media_transports();
		else
			status = pjsua_media_transports_create(&app_config[inst_id].rtp_cfg);
	}
#endif

	return status;
}

NATNL_LIB_API int WINAPI natnl_update_config_with_inst_id(struct natnl_config *cfg, int inst_id) {
	pj_status_t status;
	pj_thread_desc desc;
	pj_thread_t *thread;

	if (inst_id <= 0 || inst_id > get_max_instances())
		return PJ_EINVAL;

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	pj_thread_register(inst_id, "natnl_update_config_with_inst_id", desc, &thread);

	PJ_LOG(4, (THIS_FILE, "natnl_update_config(). inst_id=[%d]", inst_id));

#ifdef ALLOW_UPDATE_SVR_CFG
	// Check if there are existing call.
	for (i = 0; i < app_config[inst_id].cfg.max_calls; i++)
	{
		if (pjsua_var.calls[i].inv && 
			pjsua_var.calls[i].inv->state == PJSIP_INV_STATE_CONFIRMED) {
			status = NATNL_SC_TNL_ANOTHER_CALL_ALREADY_MADE;
			goto on_return;
		}
	}
#endif
	status = check_and_update_config(cfg, inst_id);

#ifdef ALLOW_UPDATE_SVR_CFG
	if (status != PJ_SUCCESS)
		goto on_return;

	return status;

on_return:
#endif
	return status;
}

NATNL_LIB_API int WINAPI natnl_update_config(struct natnl_config *cfg) {
	return natnl_update_config_with_inst_id(cfg, 1);
}

NATNL_LIB_API int WINAPI natnl_call_reinvite_with_inst_id(int call_id, int inst_id) {
	pj_status_t status = PJ_SUCCESS;
	pj_thread_desc desc;
	pj_thread_t *thread;

	if (inst_id <= 0 || inst_id > get_max_instances())
		return PJ_EINVAL;

	pj_thread_register(inst_id, "natnl_call_reinvite_with_inst_id", desc, &thread);

	PJ_LOG(4, (THIS_FILE, "natnl_call_reinvite(). inst_id=[%d], call_id=[%d]", inst_id, call_id));

	return status;
}

NATNL_LIB_API int WINAPI natnl_call_reinvite(int call_id) {
	return natnl_call_reinvite_with_inst_id(call_id, 1);
}

NATNL_LIB_API int WINAPI natnl_tunnel_port_with_inst_id(int call_id, 
						int action, int tnl_port_cnt, 
						natnl_tnl_port tnl_ports[],
						int inst_id)
{
	int i;
	int status;
	pj_thread_desc desc;
	pj_thread_t *thread;

	if (inst_id <= 0 || inst_id > get_max_instances())
		return PJ_EINVAL;

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	pj_thread_register(inst_id, "natnl_tunnel_port_with_inst_id", desc, &thread);

	status = update_tunnel_port(inst_id, call_id, action, tnl_port_cnt, tnl_ports, 0);

	PJ_LOG(4, (THIS_FILE, "natnl_tunnel_port() inst_id=[%d], call_id=[%d], action=[%d], tnl_port_cnt=[%d], tnl_stream=[%p]",
				inst_id, call_id, action, tnl_port_cnt,  pjsua_var[inst_id].calls[call_id].tnl_stream));

	if (call_id >= 0 && pjsua_var[inst_id].calls[call_id].tnl_stream)
	{
		for (i = 0; i < tnl_port_cnt; i++)
		{
			switch (action)
			{
			case 1:
				status = tunnel_srv_socket_init(inst_id, call_id, -1, tnl_ports[i].lport, tnl_ports[i].rip, tnl_ports[i].rport, 
					tnl_ports[i].qos_priority, tnl_ports[i].disable_flow_control, tnl_ports[i].speed_limit);
				if (status != PJ_SUCCESS)
					return status;
				break;
			case 2:
				status = tunnel_srv_socket_destroy(inst_id, call_id, tnl_ports[i].lport, tnl_ports[i].rport);
				if (status != PJ_SUCCESS)
					return status;
				break;
			default:

				return -1; // Unknown acation
			}
		}
	}
	return PJ_SUCCESS;
}

NATNL_LIB_API int WINAPI natnl_tunnel_port(int call_id, 
									int action, int tnl_port_cnt, 
									natnl_tnl_port tnl_ports[]) {
	return natnl_tunnel_port_with_inst_id(call_id, action, tnl_port_cnt,
		tnl_ports, 1);
}

int WINAPI natnl_instant_msg_port_with_inst_id(int action, 
									  int im_port_cnt, 
									  natnl_im_port im_ports[],
									  int inst_id) {
	int i;
	int status;
	pj_thread_desc desc;
	pj_thread_t *thread;

	if (inst_id <= 0 || inst_id > get_max_instances())
	  return PJ_EINVAL;

	if (!pjsua_var[inst_id].mutex)
	  return NATNL_SC_NOT_INITED;

	pj_thread_register(inst_id, "natnl_instant_msg_port_with_inst_id", desc, &thread);

	return update_instant_msg_port(action, im_port_cnt, im_ports, inst_id);
}

int WINAPI natnl_instant_msg_port(int action, 
						 int im_port_cnt, 
						 natnl_im_port im_ports[]) {
	 return natnl_instant_msg_port_with_inst_id(action, im_port_cnt,
		 im_ports, 1);

}

NATNL_LIB_API int WINAPI natnl_send_instant_msg_with_inst_id(
									char *dest_device_id,
									int msg_len,
									char *msg_content,
									int rport,
									int *resp_len,
									char *resp_msg,
									int inst_id)
{
	int status;
	pj_thread_desc desc;
	pj_thread_t *thread;

	char *buff = NULL;
	pj_str_t tmp_msg = pj_str(msg_content);
	char uri_to_be_send[128];
	pj_str_t tmp_uri;
	char s_rport[6];
	char s_timeout[64];
	
	struct natnl_data *user_data = NULL;
	pj_str_t *resp_body = NULL;

	if (inst_id <= 0 || inst_id > get_max_instances() || rport < 0 || rport > 65535)
		return PJ_EINVAL;

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	if (msg_len > NATNL_IM_MAX_LEN)
		return NATNL_SC_INSTANT_MSG_TOO_LONG;

	pj_thread_register(inst_id, "natnl_send_instant_msg_with_inst_id", desc, &thread);

	user_data = (struct natnl_data *)malloc(sizeof(struct natnl_data));
	user_data->status = PJ_SUCCESS;
	user_data->user_data = NULL;
	status = pj_sem_create(pjsip_get_app_pool(inst_id), "im_sem" ,0, 1, &user_data->waiting_sem);
	if (status != PJ_SUCCESS)
		goto on_return;

	memset(s_rport, 0, sizeof(s_rport));
	sprintf(s_rport, "%d", rport);
	memset(s_timeout, 0, sizeof(s_timeout));
	sprintf(s_timeout, "%d", 30);
	memset(uri_to_be_send, 0, sizeof(uri_to_be_send));
	buff = strstr(dest_device_id, "@");
	if (buff && strlen(buff) > 1) { //with sip uri
		sprintf(uri_to_be_send, "sip:%s", 
			dest_device_id);
	} else if (buff && strlen(buff) == 1) { //with '@'
		sprintf(uri_to_be_send, "sip:%s%s", 
			dest_device_id, app_config[inst_id].natnl_cfg.sip_srv[app_config[inst_id].curr_sip_idx]);
	} else {
		sprintf(uri_to_be_send, "sip:%s@%s", 
			dest_device_id, app_config[inst_id].natnl_cfg.sip_srv[app_config[inst_id].curr_sip_idx]);
	}
	tmp_uri = pj_str(uri_to_be_send);
#if 0 // always send instant message out of call.
	for (i=0; i < app_config[inst_id].natnl_cfg.max_calls; i++)
	{
		if (pjsua_var[inst_id].calls[i].media_st == PJSUA_CALL_MEDIA_ACTIVE && 
			pjsua_var[inst_id].calls[i].med_tp && 
			pjsua_var[inst_id].calls[i].med_tp->dest_uri && 
			pjsua_var[inst_id].calls[i].med_tp->dest_uri->slen) {
				if (pj_strstr(pjsua_var[inst_id].calls[i].med_tp->dest_uri, &tmp_uri))
				{
					// in call 
					status = pjsua_call_send_im(inst_id, i, NULL, &tmp_msg, NULL, s_rport, (void *)user_data);
					goto on_sent;
				}
		}
	}
#endif
	// send instant message out of call
	status = pjsua_im_send(inst_id, current_acc(inst_id), &tmp_uri, NULL, &tmp_msg, NULL, s_rport, NULL, s_timeout, (void *)user_data);
	if (status != PJ_SUCCESS) {
		goto on_return;
	}

	// wait for executing result.
	pj_sem_wait(user_data->waiting_sem);

	// prepare response message.
    resp_body = (pj_str_t *)user_data->user_data;

	if (resp_len && resp_msg) {
		if (user_data->user_data) {
			if (*resp_len < resp_body->slen) {
				*resp_len = resp_body->slen;
				status = PJ_ETOOSMALL;
				goto on_return;
			}

			memset(resp_msg, 0, *resp_len);
			memcpy(resp_msg, resp_body->ptr, resp_body->slen);
			*resp_len = resp_body->slen;
		} else {
			resp_msg = "";
		}
	}

	status = user_data->status == 200 ? 0 : user_data->status;
	if (resp_body) {
		free(resp_body->ptr);
		free(resp_body);
	}

on_return:
	if (user_data) {
		if (user_data->waiting_sem) {
			pj_sem_destroy(user_data->waiting_sem);
			user_data->waiting_sem = NULL;
		}
		free(user_data);
		user_data = NULL;
	}

	return status;
}

NATNL_LIB_API int WINAPI natnl_send_instant_msg(
									char *dest_device_id,
									int msg_len,
									char *msg_content,
									int rport,
									int *resp_len,
									char *resp_msg)
{
	return natnl_send_instant_msg_with_inst_id(dest_device_id, msg_len, msg_content, 
		rport, resp_len, resp_msg, 1);
}

NATNL_LIB_API int WINAPI natnl_send_instant_msg_to_remote_process_with_inst_id(
	char *dest_device_id,
	int msg_len,
	char *msg_content,
	char *process_name,
	int *resp_len,
	char *resp_msg,
	int inst_id)
{
	int status;
	pj_thread_desc desc;
	pj_thread_t *thread;

	char *buff = NULL;
	pj_str_t tmp_msg = pj_str(msg_content);
	char uri_to_be_send[128];
	pj_str_t tmp_uri;
	char s_timeout[64];

	struct natnl_data *user_data = NULL;
	pj_str_t *resp_body = NULL;

	if (inst_id <= 0 || inst_id > get_max_instances() || !process_name)
		return PJ_EINVAL;

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	if (msg_len > NATNL_IM_MAX_LEN)
		return NATNL_SC_INSTANT_MSG_TOO_LONG;

	pj_thread_register(inst_id, "natnl_send_instant_msg_to_remote_process_with_inst_id", desc, &thread);

	user_data = (struct natnl_data *)malloc(sizeof(struct natnl_data));
	user_data->status = PJ_SUCCESS;
	user_data->user_data = NULL;
	status = pj_sem_create(pjsip_get_app_pool(inst_id), "im_sem" ,0, 1, &user_data->waiting_sem);
	if (status != PJ_SUCCESS)
		goto on_return;

	memset(s_timeout, 0, sizeof(s_timeout));
	sprintf(s_timeout, "%d", 30);
	memset(uri_to_be_send, 0, sizeof(uri_to_be_send));
	buff = strstr(dest_device_id, "@");
	if (buff && strlen(buff) > 1) { //with sip uri
		sprintf(uri_to_be_send, "sip:%s", 
			dest_device_id);
	} else if (buff && strlen(buff) == 1) { //with '@'
		sprintf(uri_to_be_send, "sip:%s%s", 
			dest_device_id, app_config[inst_id].natnl_cfg.sip_srv[app_config[inst_id].curr_sip_idx]);
	} else {
		sprintf(uri_to_be_send, "sip:%s@%s", 
			dest_device_id, app_config[inst_id].natnl_cfg.sip_srv[app_config[inst_id].curr_sip_idx]);
	}
	tmp_uri = pj_str(uri_to_be_send);
#if 0 // always send instant message out of call.
	for (i=0; i < app_config[inst_id].natnl_cfg.max_calls; i++)
	{
		if (pjsua_var[inst_id].calls[i].media_st == PJSUA_CALL_MEDIA_ACTIVE && 
			pjsua_var[inst_id].calls[i].med_tp && 
			pjsua_var[inst_id].calls[i].med_tp->dest_uri && 
			pjsua_var[inst_id].calls[i].med_tp->dest_uri->slen) {
				if (pj_strstr(pjsua_var[inst_id].calls[i].med_tp->dest_uri, &tmp_uri))
				{
					// in call 
					status = pjsua_call_send_im(inst_id, i, NULL, &tmp_msg, NULL, s_rport, (void *)user_data);
					goto on_sent;
				}
		}
	}
#endif
	// send instant message out of call
	status = pjsua_im_send(inst_id, current_acc(inst_id), &tmp_uri, NULL, &tmp_msg, NULL, NULL, process_name, s_timeout, (void *)user_data);
	if (status != PJ_SUCCESS) {
		goto on_return;
	}

	// wait for executing result.
	pj_sem_wait(user_data->waiting_sem);

	// prepare response message.
	resp_body = (pj_str_t *)user_data->user_data;

	if (resp_len && resp_msg) {
		if (user_data->user_data) {
			if (*resp_len < resp_body->slen) {
				*resp_len = resp_body->slen;
				status = PJ_ETOOSMALL;
				goto on_return;
			}

			memset(resp_msg, 0, *resp_len);
			memcpy(resp_msg, resp_body->ptr, resp_body->slen);
			*resp_len = resp_body->slen;
		} else {
			resp_msg = "";
		}
	}

	status = user_data->status == 200 ? 0 : user_data->status;
	if (resp_body) {
		free(resp_body->ptr);
		free(resp_body);
	}

on_return:
	if (user_data) {
		if (user_data->waiting_sem) {
			pj_sem_destroy(user_data->waiting_sem);
			user_data->waiting_sem = NULL;
		}
		free(user_data);
		user_data = NULL;
	}

	return status;
}

NATNL_LIB_API int WINAPI natnl_send_instant_msg_to_remote_process(
	char *dest_device_id,
	int msg_len,
	char *msg_content,
	char *process_name,
	int *resp_len,
	char *resp_msg)
{
	return natnl_send_instant_msg_to_remote_process_with_inst_id(dest_device_id, msg_len, msg_content, 
		process_name, resp_len, resp_msg, 1);
}

NATNL_LIB_API int WINAPI natnl_read_tnl_status_with_inst_id(
	int call_id,
	int inst_id) {
	pj_thread_desc desc;
	pj_thread_t *thread;
	struct natnl_data *user_data;
	int status;

	//struct natnl_tnl_info tnl_info;

	if (inst_id <= 0 || inst_id > get_max_instances() || call_id < 0 || call_id >= app_config[inst_id].natnl_cfg.max_calls) {
		PJ_LOG(4, (THIS_FILE, "natnl_read_tnl_status_with_inst_id. status=[%d], inst_id=[%d], call_id=[%d], max_inst=[%d], max_calls=[%d]", 
			PJ_EINVAL, inst_id, call_id, get_max_instances(), app_config[inst_id].natnl_cfg.max_calls));
		return PJ_EINVAL;
	}

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	if (!pj_thread_is_registered(inst_id))
		pj_thread_register(inst_id, "natnl_read_tnl_status_with_inst_id", desc, &thread);

	user_data = &app_config[inst_id].call_user_data[call_id];
	user_data->status = PJ_SUCCESS;
	status = pj_sem_create(pjsip_get_app_pool(inst_id), "st_sem" ,0, 1, &user_data->waiting_sem);
	if (status != PJ_SUCCESS)
		goto on_return;
	//pjsua_var[inst_id].calls[call_id].user_data = user_data;

	pj_sem_wait(user_data->waiting_sem);
	status = user_data->status;

	pjsua_var[inst_id].calls[call_id].user_last_code = (pjsip_status_code)status;
	// Don't call get_tnl_info here. Due to the call->inv might be destroyed.
	//get_tnl_info(call_id, &tnl_info, inst_id, status);
	pjsua_var[inst_id].calls[call_id].user_last_code = 0;
on_return:
	if (user_data) {
		if (user_data->waiting_sem) {
			pj_sem_destroy(user_data->waiting_sem);
			user_data->waiting_sem = NULL;
		}
	}

	return status;
}

NATNL_LIB_API int WINAPI natnl_read_tnl_status(
	int call_id) {
	return natnl_read_tnl_status_with_inst_id(call_id, 1);
}

NATNL_LIB_API int WINAPI natnl_read_tnl_info_with_inst_id(
	int call_id,
	struct natnl_tnl_info *tnl_info,
	int inst_id) {
	pj_thread_desc desc;
	pj_thread_t *thread;

	if (!pj_thread_is_registered(inst_id))
		pj_thread_register(inst_id, "natnl_read_tnl_status_with_inst_id", desc, &thread);

	return get_tnl_info(call_id, tnl_info, inst_id, 0);
}

NATNL_LIB_API int WINAPI natnl_read_tnl_info(
	int call_id,
	struct natnl_tnl_info *tnl_info) {
	pj_thread_desc desc;
	pj_thread_t *thread;

	if (!pj_thread_is_registered(0))
		pj_thread_register(0, "natnl_read_tnl_status_with_inst_id", desc, &thread);

	return get_tnl_info(call_id, tnl_info, 1, 0);
}

NATNL_LIB_API int WINAPI natnl_read_tnl_transfer_speed_with_inst_id(
	int call_id,
	struct natnl_tnl_transfer_speed *transfer_speed,
	int inst_id)
{
	pjsua_call *call;
	pj_thread_desc desc;
	pj_thread_t *thread;

	if (!transfer_speed || inst_id <= 0 || inst_id > get_max_instances() || call_id < 0 || call_id >= app_config[inst_id].natnl_cfg.max_calls) {
		PJ_LOG(4, (THIS_FILE, "natnl_read_tnl_transfer_speed_with_inst_id. status=[%d], inst_id=[%d], call_id=[%d], max_inst=[%d], max_calls=[%d]", 
			PJ_EINVAL, inst_id, call_id, get_max_instances(), app_config[inst_id].natnl_cfg.max_calls));
		return PJ_EINVAL;
	}

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	pj_thread_register(inst_id, "natnl_read_tnl_transfer_speed_with_inst_id", desc, &thread);

	call = &pjsua_var[inst_id].calls[call_id];

	if (!call->inv)
		return PJ_EINVAL;

	pj_mutex_lock(call->tnl_stream_lock);
	transfer_speed->rx_speed = 0;
	transfer_speed->tx_speed = 0;
	if (call->tnl_stream) {
		transfer_speed->rx_speed = pj_bandwidthGetRawSpeed_Bps(call->tnl_stream->rx_band, 0);
		transfer_speed->tx_speed = pj_bandwidthGetRawSpeed_Bps(call->tnl_stream->tx_band, 0);
	}
	pj_mutex_unlock(call->tnl_stream_lock);

	return PJ_SUCCESS;
}

NATNL_LIB_API int WINAPI natnl_read_tnl_transfer_speed(
	int call_id,
	struct natnl_tnl_transfer_speed *transfer_speed)
{
	return natnl_read_tnl_transfer_speed_with_inst_id(call_id, transfer_speed, 1);
}

NATNL_LIB_API int WINAPI natnl_set_tnl_transfer_speed_limit_with_inst_id (
						int call_id,
						struct natnl_tnl_transfer_speed limit_speed,
						int inst_id) 
{
	pjsua_call *call;
	pj_thread_desc desc;
	pj_thread_t *thread;

	if (inst_id <= 0 || inst_id > get_max_instances() || call_id < 0 || call_id >= app_config[inst_id].natnl_cfg.max_calls) {
		PJ_LOG(4, (THIS_FILE, "natnl_set_tnl_transfer_speed_limit_with_inst_id. status=[%d], inst_id=[%d], call_id=[%d], max_inst=[%d], max_calls=[%d]", 
			PJ_EINVAL, inst_id, call_id, get_max_instances(), app_config[inst_id].natnl_cfg.max_calls));
		return PJ_EINVAL;
	}

	if (!pjsua_var[inst_id].mutex)
		return NATNL_SC_NOT_INITED;

	pj_thread_register(inst_id, "natnl_read_tnl_transfer_speed_with_inst_id", desc, &thread);
	call = &pjsua_var[inst_id].calls[call_id];
		
	if (call->tnl_stream && call->tnl_stream->rx_band) {
		if (limit_speed.rx_speed) {
			pj_bandwidthSetDesiredSpeed_Bps(call->tnl_stream->rx_band, limit_speed.rx_speed*1.1);
			pj_bandwidthSetLimited(call->tnl_stream->rx_band, PJ_TRUE);
		} else {
			pj_bandwidthSetLimited(call->tnl_stream->rx_band, PJ_FALSE);
		}
	}

	if (call->tnl_stream && call->tnl_stream->tx_band) {
		if (limit_speed.tx_speed) {
			pj_bandwidthSetDesiredSpeed_Bps(call->tnl_stream->tx_band, limit_speed.tx_speed*1.1);
			pj_bandwidthSetLimited(call->tnl_stream->tx_band, PJ_TRUE);
		} else {
			pj_bandwidthSetLimited(call->tnl_stream->tx_band, PJ_FALSE);
		}
	}

	return PJ_SUCCESS;
}

NATNL_LIB_API int WINAPI natnl_set_tnl_transfer_speed_limit (
						int call_id,
						struct natnl_tnl_transfer_speed limit_speed)
{
	return natnl_set_tnl_transfer_speed_limit_with_inst_id(call_id, limit_speed, 1);
}

NATNL_LIB_API int WINAPI natnl_detect_nat_type(
	char *stun_srv)
{
	pj_status_t status;
	int max_inst_id = get_max_instances();
	int i;
	int timeout = 0;
	int inst_id = get_max_instances() + 1;

	for (i = 1; i <= max_inst_id; i++) {
		if (pjsua_var[i].mutex) {
			inst_id = i;
			break;
		}
	}

	if (inst_id != get_max_instances() + 1) {

		pj_thread_desc desc;
		pj_thread_t *thread;

		pj_thread_register(inst_id, "natnl_detect_nat_type", desc, &thread);

		app_config[inst_id].nat_type_detected = PJ_FALSE;
		pjsua_detect_nat_type(inst_id);

		while(!app_config[inst_id].nat_type_detected && timeout <= DETECT_TIMEOUT) {
			timeout += 10;
			pj_thread_sleep(10);
		}

		if(app_config[inst_id].nat_type_detected == PJ_FALSE)
			return -1;

	} else {
		/* Create natnl */
		status = natnl_create(inst_id);
		if (status != PJ_SUCCESS)
			return -1;

		/* Initialize default config */
		default_app_config(inst_id, &app_config[inst_id]);

		/* Configure the config based on config-file */
		config_app_config(inst_id, &app_config[inst_id]);

		app_config[inst_id].cfg.stun_srv[app_config[inst_id].cfg.stun_srv_cnt++] = pj_str(stun_srv);
		app_config[inst_id].cfg.cb.on_nat_detect_natnl = &on_nat_detect; //DEAN modified

		status = natnl_init(inst_id,
			&app_config[inst_id].cfg, 
			&app_config[inst_id].log_cfg, 
			&app_config[inst_id].media_cfg);

		app_config[inst_id].nat_type_detected = PJ_FALSE;

		if (status != PJ_SUCCESS)
			goto _DETECT_NAT_ERROR;

		pjsua_detect_nat_type(inst_id);

		while(!app_config[inst_id].nat_type_detected && timeout <= DETECT_TIMEOUT) {
			timeout += 10;
			pj_thread_sleep(10);
		}
		
		if(app_config[inst_id].nat_type_detected == PJ_FALSE) {
		    PJ_LOG(4, (THIS_FILE, "Nat Detect Time out..."));	
			goto _DETECT_NAT_ERROR;
		}

		pjsua_destroy(inst_id);

		udt_cleanup();
#if !defined(PJMEDIA_DISABLE_SCTP) || (PJMEDIA_DISABLE_SCTP==0) // enable sctp
		shutdown_usrsctp();
#endif
	}

	return (int)app_config[inst_id].nat_type;

_DETECT_NAT_ERROR:
	pjsua_destroy(inst_id);
	udt_cleanup();
#if !defined(PJMEDIA_DISABLE_SCTP) || (PJMEDIA_DISABLE_SCTP==0) // enable sctp
	shutdown_usrsctp();
#endif
	return -1;
}

#if 0 // unpublished
NATNL_LIB_API int WINAPI natnl_resolve_mac_by_arp(char *targe_address, 
												  char *target_mac, 
												  int *target_mac_len, 
												  int timeout)
{
	return pj_resolve_mac_by_arp(targe_address, target_mac, 
		(pj_uint32_t *)target_mac_len, timeout);
}
#endif

NATNL_LIB_API char * WINAPI natnl_lib_version(void)
{
	return NATNL_LIB_VERSION;
}

#endif

void printVersion() 
{
	//printf("----------------------------------------------------\n");
	PJ_LOG(3, (THIS_FILE, "ASUSTek COMPUTER INC."));
	PJ_LOG(3, (THIS_FILE, "ASUS NAT Tunnel Library Version :	%s", NATNL_LIB_VERSION));
	PJ_LOG(3, (THIS_FILE, "ASUS NAT Execution Version      : %s", NATNL_EXE_VERSION));
	//printf("----------------------------------------------------\n");
}

//#if TEST_NETWORK==1
#if 0
#include <networkIface.h>
#include <adv_inet.h>
int GetIP_Info()
{
	int 	OutBufLen 	= 0;
	int 	ret		= 0;		
	int	i		= 0;
	P_ADAPTER_INFO pAdapter_info=NULL, p=NULL;
	ret = GetAdaptersInfo(NULL, NULL);
	PJ_LOG(4, (THIS_FILE, "ret len = %d", ret));
	
	OutBufLen =ret*sizeof(ADAPTER_INFO); 
	MALLOC(pAdapter_info, ADAPTER_INFO, OutBufLen);
	GetAdaptersInfo(pAdapter_info,&OutBufLen);
	PJ_LOG(4, (THIS_FILE, "OutBufLen = %d ",OutBufLen ));
	for (p = pAdapter_info; p;p = p->Next){
		//PJ_LOG(4, (THIS_FILE, "Interface [%d]", i));
		PJ_LOG(4, (THIS_FILE, "NAME = %s, ADDR=%d, BROADADDR=%d, NETMASK=%d, FLAGS=%d, MTU=%d", pAdapter_info->IFR_NAME, pAdapter_info->IFR_ADDR, pAdapter_info->IFR_BROADADDR, pAdapter_info->IFR_NETMASK,  pAdapter_info->IFR_FLAGS, pAdapter_info->IFR_MTU ));
		char addr_buf[32];memset(addr_buf, 0, 32);
		PJ_LOG(4, (THIS_FILE, "ip addr  = %s ",AdvInet_NtoA(pAdapter_info->IFR_ADDR, addr_buf) ));
	}
	return 0;
}
#endif
