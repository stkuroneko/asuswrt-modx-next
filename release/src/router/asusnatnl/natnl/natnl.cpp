#include <natnl.h>
#include <natnl_codec.h>

#include <pjmedia/stream.h>
#include <pjmedia/natnl_stream.h>
#include <message.h>
// +Roger
#ifdef WIN32
#include <windows.h>
#endif

//#include <pjsua-lib/pjsua_internal.h>
#include <udt.h>
#include <client.h>
#include <natnl_lib.h>
#include <im_handler.h>
#include <limits.h>

//----------------------------------//

#define THIS_FILE   "natnl.c"

//#if  defined(NATNL_LIB) && !defined(PJ_ANDROID) && PJ_CONFIG_IPHONE!=1
//char callee[128], registrar_uri[128];
//#endif

/* external functions */
#if 0
extern int tunnel_accept(pjsua_inst_id inst_id, pjsua_call_id call_id, int udt_sock);
#endif
extern int tunnel_run(pjsua_inst_id inst_id, pjsua_call_id call_id, pjmedia_transport *tp);
extern int natnl_handle_recv_msg(pjsua_call_id call_id, pjmedia_transport *tp, 
								 char *data, int data_len);

#define cleartimer(tvp)         (tvp)->sec = (tvp)->msec = 0

static void restart_ka_check_timer(pjmedia_transport *tp);
static void restart_idle_check_timer(pjmedia_transport *tp);
extern PJ_DEF(pj_stun_nat_type) natnl_get_nat_type(int inst_id);
extern PJ_DEF(void *) natnl_get_app_data(int inst_id);
extern PJ_DEF(void *) natnl_get_call_user_data(int inst_id, int call_id);
extern PJ_DEF(pjsua_logging_config *) natnl_get_app_config(int inst_id);
extern void on_tunnel_complete(pjsua_call *call, pj_status_t status);
extern PJ_DEF(void) natnl_set_call_hangup_mode(int inst_id, int call_id, int value);
struct natnl_callback natnl_callback;

enum ka_timer
{
	TIMER_NONE,							/**< Timer not active			*/
	TIMER_TIMEOUT_RECV_KEEP_ALIVE		/**< ICE keep-alive timer.		*/
};
enum idle_check_timer
{
	IDLE_CHECK_TIMER_NONE,							/**< Timer not active			*/
	IDLE_CHECK_TIMER_IDLE							/**< Idle.		*/
};

/* Notification on incoming request */
static pj_bool_t options_on_rx_request(pjsip_rx_data *rdata)
{
    pjsip_tx_data *tdata;
    pjsip_response_addr res_addr;
    pjmedia_transport_info tpinfo;
    pjmedia_sdp_session *sdp;
    const pjsip_hdr *cap_hdr;
	pj_status_t status;
	pjsua_inst_id inst_id = rdata->tp_info.pool->factory->inst_id;

    /* Only want to handle OPTIONS requests */
    if (pjsip_method_cmp(&rdata->msg_info.msg->line.req.method,
                         pjsip_get_options_method()) != 0)
    {
        return PJ_FALSE;
    }

    /* Don't want to handle if shutdown is in progress */
    if (pjsua_var[inst_id].thread_quit_flag) {
        pjsip_endpt_respond_stateless(pjsua_var[inst_id].endpt, rdata, 
                                      PJSIP_SC_TEMPORARILY_UNAVAILABLE, NULL,
                                      NULL, NULL);
        return PJ_TRUE;
    }

    /* Create basic response. */
    status = pjsip_endpt_create_response(pjsua_var[inst_id].endpt, rdata, 200, NULL, 
                                         &tdata);
    if (status != PJ_SUCCESS) {
        pjsua_perror(THIS_FILE, "Unable to create OPTIONS response", status);
        return PJ_TRUE;
    }

    /* Add Allow header */
    cap_hdr = pjsip_endpt_get_capability(pjsua_var[inst_id].endpt, PJSIP_H_ALLOW, NULL);
    if (cap_hdr) {
        pjsip_msg_add_hdr(tdata->msg, 
                          (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, cap_hdr));
    }

    /* Add Accept header */
    cap_hdr = pjsip_endpt_get_capability(pjsua_var[inst_id].endpt, PJSIP_H_ACCEPT, NULL);
    if (cap_hdr) {
        pjsip_msg_add_hdr(tdata->msg, 
                          (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, cap_hdr));
    }

    /* Add Supported header */
    cap_hdr = pjsip_endpt_get_capability(pjsua_var[inst_id].endpt, PJSIP_H_SUPPORTED, NULL);
    if (cap_hdr) {
        pjsip_msg_add_hdr(tdata->msg, 
                          (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, cap_hdr));
	}

#if !defined(PJMEDIA_DISABLE_SCTP) || (PJMEDIA_DISABLE_SCTP == 0)
	/* Add Supported header */
	cap_hdr = pjsip_endpt_get_capability(pjsua_var[inst_id].endpt, PJSIP_H_TNL_SUPPORTED, NULL);
	if (cap_hdr) {
		pjsip_msg_add_hdr(tdata->msg, 
			(pjsip_hdr*) pjsip_hdr_clone(tdata->pool, cap_hdr));
	}
#endif

    /* Add Allow-Events header from the evsub module */
    cap_hdr = pjsip_evsub_get_allow_events_hdr(NULL);
    if (cap_hdr) {
        pjsip_msg_add_hdr(tdata->msg, 
                          (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, cap_hdr));
    }

    /* Add User-Agent header */
    if (pjsua_var[inst_id].ua_cfg.user_agent.slen) {
        const pj_str_t USER_AGENT = { "User-Agent", 10};
        pjsip_hdr *h;

        h = (pjsip_hdr*) pjsip_generic_string_hdr_create(tdata->pool,
                                                         &USER_AGENT,
                                                         &pjsua_var[inst_id].ua_cfg.user_agent);
        pjsip_msg_add_hdr(tdata->msg, h);
    }

    /* Get media socket info, make sure transport is ready */
    if (pjsua_var[inst_id].calls[0].med_tp) {
        pjmedia_transport_info_init(&tpinfo);
        pjmedia_transport_get_info(pjsua_var[inst_id].calls[0].med_tp, &tpinfo);

        /* Add SDP body, using call0's RTP address */
        status = pjmedia_endpt_create_sdp(pjsua_var[inst_id].med_endpt, tdata->pool, 1,
                                          &tpinfo.sock_info, &sdp);
        if (status == PJ_SUCCESS) {
            pjsip_create_sdp_body(tdata->pool, sdp, &tdata->msg->body);
        }
    }

    /* Send response statelessly */
    pjsip_get_response_addr(tdata->pool, rdata, &res_addr);
    status = pjsip_endpt_send_response(pjsua_var[inst_id].endpt, &res_addr, tdata, NULL, NULL);
    if (status != PJ_SUCCESS)
        pjsip_tx_data_dec_ref(tdata);

    return PJ_TRUE;
}

/* The module instance. */
static pjsip_module pjsua_options_handler = 
{
    NULL, NULL,				/* prev, next.		*/
    { "mod-pjsua-options", 17 },	/* Name.		*/
    -1,					/* Id			*/
    PJSIP_MOD_PRIORITY_APPLICATION,	/* Priority	        */
    NULL,				/* load()		*/
    NULL,				/* start()		*/
    NULL,				/* stop()		*/
    NULL,				/* unload()		*/
    &options_on_rx_request,		/* on_rx_request()	*/
    NULL,				/* on_rx_response()	*/
    NULL,				/* on_tx_request.	*/
    NULL,				/* on_tx_response()	*/
    NULL,				/* on_tsx_state()	*/

};

/*****************************************************************************
 * These two functions are the main callbacks registered to PJSIP stack
 * to receive SIP request and response messages that are outside any
 * dialogs and any transactions.
 */

/*
 * Handler for receiving incoming requests.
 *
 * This handler serves multiple purposes:
 *  - it receives requests outside dialogs.
 *  - it receives requests inside dialogs, when the requests are
 *    unhandled by other dialog usages. Example of these
 *    requests are: MESSAGE.
 */
static pj_bool_t mod_pjsua_on_rx_request(pjsip_rx_data *rdata)
{
	pj_bool_t processed = PJ_FALSE;
	pjsua_inst_id inst_id = rdata->tp_info.pool->factory->inst_id;

    PJSUA_LOCK(inst_id);

    if (rdata->msg_info.msg->line.req.method.id == PJSIP_INVITE_METHOD) {

	processed = pjsua_call_on_incoming(rdata);
    }

    PJSUA_UNLOCK(inst_id);

    return processed;
}


/*
 * Handler for receiving incoming responses.
 *
 * This handler serves multiple purposes:
 *  - it receives strayed responses (i.e. outside any dialog and
 *    outside any transactions).
 *  - it receives responses coming to a transaction, when pjsua
 *    module is set as transaction user for the transaction.
 *  - it receives responses inside a dialog, when these responses
 *    are unhandled by other dialog usages.
 */
static pj_bool_t mod_pjsua_on_rx_response(pjsip_rx_data *rdata)
{
    PJ_UNUSED_ARG(rdata);
    return PJ_FALSE;
}


// +Roger - Keepalive Callback
static void ka_timer(pj_timer_heap_t *th, struct pj_timer_entry *te)
{
    pjsua_call *call = (pjsua_call*)te->user_data;

	enum ka_timer type = (enum ka_timer)te->id;

    int timer_id = te->id;

    te->id = TIMER_NONE;

    PJ_UNUSED_ARG(th);

    switch (timer_id) {
    case TIMER_TIMEOUT_RECV_KEEP_ALIVE:
	{
		pj_timestamp last_data_or_ka, now;
		pj_uint32_t elapsed_time;

		last_data_or_ka = call->tnl_stream->last_data_or_ka;

		pj_get_timestamp(&now);

		elapsed_time = pj_elapsed_msec(&last_data_or_ka, &now);
		PJ_LOG(4, (THIS_FILE, "ka_timer(), inst_id=[%d], call_id=[%d], elapsed_time=[%d]", call->inst_id, call->index, elapsed_time/1000));

		restart_ka_check_timer(call->med_tp);
		// Data was received in tnl_timeout_sec time, don't notify NATNL_TNL_EVENT_KA_TIMEOUT.
		if (elapsed_time < pjsua_var[call->inst_id].tnl_timeout_msec)
			return;
		else {
			if (natnl_callback.on_natnl_tnl_event) {
				// Callback Event
				struct natnl_tnl_event tnl_event;
				struct pjmedia_transport *tp = (struct pjmedia_transport *)pjsua_var[call->inst_id].calls[call->index].med_tp;
				memset(&tnl_event, 0, sizeof(tnl_event));
			
				tnl_event.inst_id = call->inst_id;
				if (tnl_event.inst_id >= 1)
					tnl_event.app_data = natnl_get_app_data(tnl_event.inst_id);
				tnl_event.call_id = call->index;

				tnl_event.event_code = NATNL_TNL_EVENT_KA_TIMEOUT;
				tnl_event.status_code = (natnl_status_code)NATNL_TNL_EVENT_KA_TIMEOUT;

				if (pjsua_var[call->inst_id].calls[call->index].med_tp_st != PJSUA_MED_TP_IDLE)
					tnl_event.ua_type = pjsua_var[call->inst_id].calls[call->index].inv->role+1;
				else
					tnl_event.ua_type = 0;

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

				tnl_event.tnl_type = call->med_tp->tunnel_type;
				tnl_event.nat_type = natnl_get_nat_type(call->inst_id);
				//natnl_callback.on_natnl_tnl_event(&tnl_event);
				natnl_call_callback(&tnl_event);
			}

			PJ_LOG(2, (THIS_FILE, "ka_timer(), !!!! TUNNEL TIMEOUT !!!! inst_id=[%d], call_id=[%d]", call->inst_id, call->index));

			natnl_set_call_hangup_mode(call->inst_id, call->index, 1); // To avoid re-invite timer trigger.
			pjsua_call_hangup(call->inst_id, call->index, NATNL_SC_TNL_TIMEOUT, NULL, NULL);
		}
	}
	break;

    default:
		pj_assert(!"Unknown timer");
	break;
    }
}

// +Roger - check timer
static void restart_ka_check_timer(pjmedia_transport *tp) {
	if(tp->tnl_ka_to_chk_timer.id > 0) {
		pj_timer_heap_cancel(pjsua_var[tp->inst_id].stun_cfg.timer_heap,
			&tp->tnl_ka_to_chk_timer);
		tp->tnl_ka_to_chk_timer.id = TIMER_NONE;
	}

	tp->tnl_ka_to_chk_timer.id = TIMER_NONE;
	// natnl added for check remote ua's keep alive packet
	if (tp->tnl_ka_to_chk_timer.id == TIMER_NONE) {
		pj_time_val delay = { 0, 0 };

		tp->tnl_ka_to_chk_timer.id = TIMER_TIMEOUT_RECV_KEEP_ALIVE;
		delay.msec = pjsua_var[tp->inst_id].tnl_timeout_msec;
		pj_time_val_normalize(&delay);

		pj_timer_heap_schedule(pjsua_var[tp->inst_id].stun_cfg.timer_heap, 
			&tp->tnl_ka_to_chk_timer, &delay);
	}

}
// +Dean - idle check timer
static void idle_check_timer(pj_timer_heap_t *th, struct pj_timer_entry *te)
{
	pjsua_call *call = (pjsua_call*)te->user_data;

	enum ka_timer type = (enum ka_timer)te->id;

	int timer_id = te->id;

	te->id = TIMER_NONE;

	PJ_UNUSED_ARG(th);

	switch (timer_id) {
	case IDLE_CHECK_TIMER_IDLE:
	{
		pj_timestamp last_data, now;
		pj_uint32_t elapsed_time;

		last_data = call->tnl_stream->last_data;

		pj_get_timestamp(&now);

		elapsed_time = pj_elapsed_msec(&last_data, &now);
		PJ_LOG(4, (THIS_FILE, "idle_check_timer(), inst_id=[%d], call_id=[%d], elapsed_time=[%d]", call->inst_id, call->index, elapsed_time/1000));

		restart_idle_check_timer(call->med_tp);
		// Data was received in tnl_timeout_sec time, don't notify NATNL_TNL_EVENT_KA_TIMEOUT.
		if (elapsed_time < pjsua_var[call->inst_id].idle_timeout_msec)
			return;
		else {
			struct natnl_data *user_data = (struct natnl_data *)natnl_get_call_user_data(call->inst_id, call->index);
			PJ_LOG(2, (THIS_FILE, "idle_check_timer(), !!!! IDLE TIMEOUT !!!! inst_id=[%d], call_id=[%d]", call->inst_id, call->index));
			
			if (user_data && user_data->waiting_sem) {
				user_data->status = NATNL_SC_IDLE_TIMEOUT;
				pj_sem_post(user_data->waiting_sem);
			}

			if (natnl_callback.on_natnl_tnl_event) {
				// Callback Event
				struct natnl_tnl_event tnl_event;
				struct pjmedia_transport *tp = (struct pjmedia_transport *)pjsua_var[call->inst_id].calls[call->index].med_tp;
				memset(&tnl_event, 0, sizeof(tnl_event));

				tnl_event.inst_id = call->inst_id;
				if (tnl_event.inst_id >= 1)
					tnl_event.app_data = natnl_get_app_data(tnl_event.inst_id);
				tnl_event.call_id = call->index;
				tnl_event.event_code = NATNL_TNL_EVENT_IDLE_TIMEOUT;
				tnl_event.status_code = (natnl_status_code)NATNL_TNL_EVENT_IDLE_TIMEOUT;

				if (pjsua_var[call->inst_id].calls[call->index].med_tp_st != PJSUA_MED_TP_IDLE)
					tnl_event.ua_type = pjsua_var[call->inst_id].calls[call->index].inv->role+1;
				else
					tnl_event.ua_type = 0;

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

				tnl_event.tnl_type = call->med_tp->tunnel_type;
				tnl_event.nat_type = natnl_get_nat_type(call->inst_id);
				//natnl_callback.on_natnl_tnl_event(&tnl_event);
				natnl_call_callback(&tnl_event);
			}
		}
	}
		break;

	default:
		pj_assert(!"Unknown timer");
		break;
	}
}

// +Roger - check timer
static void restart_idle_check_timer(pjmedia_transport *tp) {
	if(tp->tnl_idle_chk_timer.id > 0) {
		pj_timer_heap_cancel(pjsua_var[tp->inst_id].stun_cfg.timer_heap,
			&tp->tnl_idle_chk_timer);
		tp->tnl_idle_chk_timer.id = TIMER_NONE;
	}

	if (pjsua_var[tp->inst_id].idle_timeout_msec > 0)
	{
		tp->tnl_idle_chk_timer.id = TIMER_NONE;
		// natnl added for check remote ua's keep alive packet
		if (tp->tnl_idle_chk_timer.id == TIMER_NONE) {
			pj_time_val delay = { 0, 0 };

			tp->tnl_idle_chk_timer.id = IDLE_CHECK_TIMER_IDLE;
			delay.msec = pjsua_var[tp->inst_id].idle_timeout_msec;
			pj_time_val_normalize(&delay);

			pj_timer_heap_schedule(pjsua_var[tp->inst_id].stun_cfg.timer_heap, 
				&tp->tnl_idle_chk_timer, &delay);
		}
	}

}

/* Worker thread function. */
static int worker_thread(void *arg)
{
	enum { TIMEOUT = 10};

	//PJ_UNUSED_ARG(arg);
	pjsua_inst_id inst_id = pjsip_endpt_get_inst_id((pjsip_endpoint *)arg);

	PJ_LOG(3, (THIS_FILE, "!!!WORKER THREAD CREATED!!! [tid=%d]", pj_gettid()));

	while (!pjsua_var[inst_id].thread_quit_flag) {
		int count;

		pj_get_timestamp(&pjsua_var[inst_id].worker_thread_ts);

		count = pjsua_handle_events(inst_id, TIMEOUT);
		if (count < 0)
			pj_thread_sleep(TIMEOUT);
//charles test for cpu loading
	//		pj_thread_sleep(10);

	}

	return 0;
}


/* Monitor thread function. */
static int monitor_thread(void *arg)
{
	pj_bool_t log_enabled = PJ_FALSE;

	enum { TIMEOUT = 10};

	//PJ_UNUSED_ARG(arg);
	pjsua_inst_id inst_id = pjsip_endpt_get_inst_id((pjsip_endpoint *)arg);

	PJ_LOG(3, (THIS_FILE, "!!!MONITOR THREAD CREATED!!! [tid=%d]", pj_gettid()));

	while (!pjsua_var[inst_id].thread_quit_flag) {
		pjsua_logging_config cfg;
		pj_uint32_t elapsed_time;
		pj_timestamp now;


		// Log flag file.
		if (!log_enabled) {
			if (pjsua_var[0].log_cfg.log_flag_file.slen && 
				pj_file_exists(pjsua_var[0].log_cfg.log_flag_file.ptr)) {
				pjsua_logging_config_dup(pjsua_var[inst_id].pool, &cfg, &pjsua_var[inst_id].log_cfg);
				cfg.level = 4;
				cfg.log_file_flags |= PJ_O_APPEND;
				cfg.log_file_flags &= ~PJ_O_SYSLOG;
				pjsua_reconfigure_logging(0, &cfg);
				log_enabled = PJ_TRUE;
			}
		} else {
			if (pjsua_var[0].log_cfg.log_flag_file.slen && 
				!pj_file_exists(pjsua_var[0].log_cfg.log_flag_file.ptr)) {
				pjsua_logging_config *log_cfg = natnl_get_app_config(0);
				pjsua_logging_config_dup(pjsua_var[inst_id].pool, &cfg, &pjsua_var[inst_id].log_cfg);
				cfg.level = log_cfg->level;
				cfg.log_file_flags = log_cfg->log_file_flags;
				pjsua_reconfigure_logging(0, &cfg);
				log_enabled = PJ_FALSE;
			}
		}

		// Check worker thread
		if (pjsua_var[inst_id].worker_thread_ts.u64 != 0) {
				pj_get_timestamp(&now);

				elapsed_time = pj_elapsed_msec(&pjsua_var[inst_id].worker_thread_ts, &now);
				if (elapsed_time > 60000 && natnl_callback.on_natnl_tnl_event) {
					// Callback Event
					struct natnl_tnl_event tnl_event;
					memset(&tnl_event, 0, sizeof(tnl_event));

					tnl_event.inst_id = inst_id;
					if (tnl_event.inst_id >= 1)
						tnl_event.app_data = natnl_get_app_data(tnl_event.inst_id);
					tnl_event.event_code = NATNL_TNL_EVENT_DEADLOCK;
					tnl_event.status_code = (natnl_status_code)NATNL_TNL_EVENT_DEADLOCK;
					natnl_call_callback(&tnl_event);
				}
		}

		pj_thread_sleep(3000);
	}

	return 0;
}

// +Roger - UDT Thread
// DEAN merge UDT and TCP thread
/* NATNL thread function. */
int natnl_send_thread(void *arg)
{

#define PKT_SIZE 1000

	enum { TIMEOUT = 1};
	int count = 0;

	pjsua_call *call = (pjsua_call *)arg;
	pjsua_call_id call_id = call->index;
	pjsua_inst_id inst_id = call->inst_id;


    pj_status_t status = PJ_SUCCESS;
    pj_uint32_t ith = 0;

    pj_uint8_t pkt[PKT_SIZE] = {0};
    //int sz = 0;
	pj_ssize_t sz = 0;	// +Roger

	pj_grp_lock_add_ref(call->tnl_stream->grp_lock);

	PJ_LOG(4, (THIS_FILE, "natnl_send_thread() inst_id=%d, call_id=%d, delay_cnt=%d", inst_id, call_id, SND_THREAD_DELAY_CNT));


	call->med_tp->call_id = call_id; // 2013-06-21 DEAN, for later use.
	call->med_tp->inst_id = inst_id; // 2013-06-21 DEAN, for later use.

	//stream = call->tnl_stream;
	call->tnl_stream->med_tp = call->med_tp;		// +Roger - pointer to med_tp
	call->tnl_stream->med_tp->tunnel_type = call->med_tp->tunnel_type;	// +Roger - overwritten

	// +Roger - Register Thread
	pj_thread_desc desc;
	pj_thread_t *thread = 0;
	if (!pj_thread_is_registered(inst_id)) {
		int status = pj_thread_register(inst_id, "natnl_udt_send_thread", desc, &thread);
		if (status != PJ_SUCCESS) {
			try {
				throw CUDTException(3, 1);
			} catch (...) {
				PJ_LOG(1, ("natnl.c", "natnl_send_thread() pj_thread_register failed status=%d", status));
				goto THRD_TERMINATE;
			}
		}
	}

	status = pj_thread_set_prio(pj_thread_this(inst_id), pj_thread_get_prio_max(pj_thread_this(inst_id)));
	if (status != PJ_SUCCESS)
		PJ_LOG(1, ("natnl.c", "natnl_send_thread() pj_thread_set_prio failed status=%d", status));

	PJ_LOG(4, (THIS_FILE, "!!!SEND THREAD CREATED!!! [tid=%d]", pj_gettid()));

	while (call->tnl_stream && !pjsua_var[inst_id].thread_quit_flag && 
		!call->tnl_stream->thread_quit_flag) {

			tunnel_run(inst_id, call_id, call->med_tp);

#if 1  // TODO power saving option
			if (count >= SND_THREAD_DELAY_CNT) {
				pj_thread_sleep(TIMEOUT);
				count = 0;
			}
			count++;
#endif
	}
THRD_TERMINATE:
	PJ_LOG(2, (THIS_FILE, "natnl_send_thread terminated. call_id=[%d]", call->index));
	pj_grp_lock_dec_ref(call->tnl_stream->grp_lock);
	return 0;
}

int natnl_no_ctl_recv_thread(void *arg)
{

	pj_status_t status = PJ_SUCCESS;
	pj_uint32_t ith = 0;

	pj_uint8_t pkt[PKT_SIZE] = {0};
	pj_ssize_t sz = 0; // +Roger

	pjsua_call *call = (pjsua_call *)arg;
	pjsua_call_id call_id = call->index;
	pjsua_inst_id inst_id = call->inst_id;

	pj_thread_desc desc;
	pj_thread_t *thread = 0;

	pj_grp_lock_add_ref(call->tnl_stream->grp_lock);

	// DEAN, prevent assert fail while garbage collector remove UDT socket on multiple instance. 
	if (!pj_thread_is_registered(call->inst_id)) {
		int status = pj_thread_register(call->inst_id, "natnl_no_ctl_recv_thread", desc, &thread );
		if (status != PJ_SUCCESS) {
			pj_grp_lock_dec_ref(call->tnl_stream->grp_lock);
			return -1;
		}
	}

	PJ_LOG(4, (THIS_FILE, "!!!NO CONTROL RECV THREAD CREATED!!! [tid=%d]", pj_gettid()));

	while (call->tnl_stream && !pjsua_var[inst_id].thread_quit_flag && 
		!call->tnl_stream->thread_quit_flag) 
	{
		char buff[2000] = {0};
		recv_buff *rb = NULL;

		if(call == NULL) {
			pj_grp_lock_dec_ref(call->tnl_stream->grp_lock);
			return -1;
		}

		if(call->tnl_stream==NULL) {
			pj_grp_lock_dec_ref(call->tnl_stream->grp_lock);
			return -1;
		}

		pj_mutex_lock(call->tnl_stream_lock4);

		natnl_stream *stream = (natnl_stream *)call->tnl_stream;

		//get data from rBuff
		if (stream == NULL) {
			pj_mutex_unlock(call->tnl_stream_lock4);
			pj_grp_lock_dec_ref(call->tnl_stream->grp_lock);
			return -1;
		}
		// charles CHARLES
		// DEAN commeted, for using pj_sem_try_wait2
		//pj_mutex_unlock(call->tnl_stream_lock3);
		//pj_sem_wait(stream->rbuff_sem);
		pj_sem_trywait2(stream->no_ctl_rbuff_sem);
		//pj_mutex_lock(call->tnl_stream_lock3);

		pj_mutex_lock(stream->no_ctl_rbuff_mutex);

		if (!pj_list_empty(&stream->no_ctl_rbuff)) {
			rb = stream->no_ctl_rbuff.next;
			stream->no_ctl_rbuff_cnt--;
			//PJ_LOG(4, ("channel.cpp", "rbuff_cnt=%d", stream->rbuff_cnt));
			pj_list_erase(rb);
		}
		pj_mutex_unlock(stream->no_ctl_rbuff_mutex);

		if (rb != NULL) {
			if (rb->len > 0 && 
				((pj_uint32_t *)rb->buff)[0] == NO_FLOW_CTL_MAGIC()) {  // check the magic
				char *data = (char *)&rb->buff[NO_FLOW_CTL_SESS_MGR_HEADER_MAGIC_SIZE];
				int len = rb->len - NO_FLOW_CTL_SESS_MGR_HEADER_MAGIC_SIZE;
				natnl_handle_recv_msg(call_id, call->tnl_stream->med_tp, data, len);
			} else // UDT socket may be closed. It causes natnl_recv_thread can't work properly. Sleep 10ms .
				pj_thread_sleep(10);   
#if 0
			//move rb to gcbuff
			pj_mutex_lock(stream->gcbuff_mutex);
			pj_list_push_back(&stream->gcbuff, rb);
			pj_mutex_unlock(stream->gcbuff_mutex);
#else
			free(rb);
			rb = NULL;
#endif
		}

		pj_mutex_unlock(call->tnl_stream_lock4);
	}
	PJ_LOG(2, (__FILE__, "natnl_no_ctl_recv_thread terminated and call tunnel complete. call_id=[%d]", call->index));
	pj_grp_lock_dec_ref(call->tnl_stream->grp_lock);
	return 0;
}

// +Roger - UDT Thread
// DEAN merge UDT and TCP thread
/* NATNL thread function. */
//int PJ_THREAD_FUNC natnl_udt_thread(void *arg)
int natnl_recv_thread(void *arg)
{
    pj_status_t status = PJ_SUCCESS;
    pj_uint32_t ith = 0;

    pj_uint8_t pkt[PKT_SIZE] = {0};
    pj_ssize_t sz = 0; // +Roger

    enum {
        TIMEOUT = 1
    };

    int count = 0;

	pjsua_call *call = (pjsua_call *)arg;
	pjsua_call_id call_id = call->index;
	pjsua_inst_id inst_id = call->inst_id;

	struct sockaddr_in local_addr, remote_addr;
	pjmedia_transport *tp;

	char addrinfo1[PJ_INET6_ADDRSTRLEN+10];
	char addrinfo2[PJ_INET6_ADDRSTRLEN+10];

	pjmedia_stream_info *stream_info;

	pj_grp_lock_add_ref(call->tnl_stream->grp_lock);

	pjmedia_session_get_stream_info(call->session, call->audio_idx, &stream_info);

	memset((void *) &remote_addr, 0, sizeof(struct sockaddr_in));
	memset((void *) &local_addr, 0, sizeof(struct sockaddr_in));

    PJ_LOG(4, (__FILE__, "natnl_recv_thread() inst_id=%d, call_id=%d, loc_addr=%s, rem_addr=%s", inst_id, call_id, 
		pj_sockaddr_print(&call->med_rtp_addr, addrinfo1, sizeof(addrinfo1), 3),
		pj_sockaddr_print(&stream_info->rem_addr, addrinfo2, sizeof(addrinfo2), 3)));

    //pjsua_call *call = &pjsua_var.calls[call_id];

	// +Roger
	cleartimer(&call->keep_alive);
	pj_timer_entry_init(&call->tnl_ka_to_chk_timer, TIMER_NONE, (void*)call, &ka_timer);
	memcpy(&call->med_tp->tnl_ka_to_chk_timer, &call->tnl_ka_to_chk_timer, sizeof(pj_timer_entry));

	pj_timer_entry_init(&call->tnli_idle_chk_timer, TIMER_NONE, (void*)call, &idle_check_timer);
	memcpy(&call->med_tp->tnl_idle_chk_timer, &call->tnli_idle_chk_timer, sizeof(pj_timer_entry));

    //stream = call->tnl_stream;
    call->tnl_stream->med_tp = call->med_tp;  // +Roger - pointer to med_tp
	call->tnl_stream->med_tp->tunnel_type = call->med_tp->tunnel_type; // +Roger - overwritten
	tp = call->tnl_stream->med_tp;

    // +Roger - Register Thread
    pj_thread_desc desc;
    pj_thread_t *thread = 0;
    if (!pj_thread_is_registered(inst_id)) {
        int status = pj_thread_register(inst_id, "natnl_recv_thread", desc, &thread);
		if (status != PJ_SUCCESS) {
			//return -1;
			try {
				throw CUDTException(3, 1);
			} catch (...) {
				PJ_LOG(1, ("natnl.c", "natnl_recv_thread() pj_thread_register failed status=%d", status));
				goto THRD_TERMINATE_CALL_TUNNEL_COMPLETE;
			}
		}
	}

	status = pj_thread_set_prio(pj_thread_this(inst_id), pj_thread_get_prio_max(pj_thread_this(inst_id)));
	if (status != PJ_SUCCESS)
		PJ_LOG(1, ("natnl.c", "natnl_recv_thread() pj_thread_set_prio failed status=%d", status));

	if (!tp->use_sctp) {
		//in udt_socket, will setsockopt UDT_RENDEZVOUS and bind socket to natnl_stream
		call->tnl_stream->udt_sock = udt_socket();
		call->tnl_stream->med_tp->udt_sock = call->tnl_stream->udt_sock;

		status = udt_bind((void *)call);
		if (status != PJ_SUCCESS) {
			status = NATNL_SC_UDT_CONNECT_FAILED;
			PJ_LOG(1, ("natnl.c", "natnl_recv_thread() udt_bind failed status=%d", status));
			udt_close(call);
			goto THRD_TERMINATE_CALL_TUNNEL_COMPLETE;
		}
		
		status = udt_connect((void *)call);
		if (status != PJ_SUCCESS) {
			status = NATNL_SC_UDT_CONNECT_FAILED;
			PJ_LOG(1, ("natnl.c", "natnl_recv_thread() udt_connect failed status=%d", status));
			udt_close(call);
			goto THRD_TERMINATE_CALL_TUNNEL_COMPLETE;
		}
	}

	status = pj_thread_create(call->tnl_stream->pool, "natnl_send_thread", &natnl_send_thread,  
		(void *)call, 0, 0,
		&call->tnl_stream->send_thread);
	if (status != PJ_SUCCESS) {
		PJ_LOG(1, ("natnl.c", "natnl_recv_thread() pj_thread_create natnl_send_thread failed status=%d", status));
		udt_close(call);
		goto THRD_TERMINATE_CALL_TUNNEL_COMPLETE;
	}

	/*status = pj_thread_create(pjsua_var[inst_id].pool, "natnl_no_ctl_recv_thread", &natnl_no_ctl_recv_thread,  
		(void *)call, 0, 0,
		&call->tnl_stream->no_ctl_recv_thread);
	if (status != PJ_SUCCESS) {
		PJ_LOG(1, ("natnl.c", "natnl_recv_thread() pj_thread_create natnl_no_ctl_recv_thread failed status=%d", status));
		udt_close(call);
		goto THRD_TERMINATE_CALL_TUNNEL_COMPLETE;
	}*/

	restart_ka_check_timer(call->med_tp);
	restart_idle_check_timer(call->med_tp);

	PJ_LOG(4, (THIS_FILE, "!!!RECV THREAD CREATED!!! [tid=%d]", pj_gettid()));

	on_tunnel_complete(call, status);

    while (call->tnl_stream && !pjsua_var[inst_id].thread_quit_flag && 
           !call->tnl_stream->thread_quit_flag) 
    {
		char buff[2000] = {0};

		if (!call->session) {
			//PJ_LOG(1, (THIS_FILE, "natnl_tcp_thread terminated."));
			continue;
		}

		if (tp->use_sctp) {
			recv_buff *rb = NULL;
			natnl_stream *stream = NULL;

			pj_mutex_lock(call->tnl_stream_lock3);

			stream = (natnl_stream *)call->tnl_stream;

			//get data from rBuff
			if (stream == NULL) {
				pj_mutex_unlock(call->tnl_stream_lock3);
				continue;
			}
			pj_sem_wait(stream->rbuff_sem);

			pj_mutex_lock(stream->rbuff_mutex);

			if (!pj_list_empty(&stream->rbuff)) {
				rb = stream->rbuff.next;
				stream->rbuff_cnt--;
				pj_list_erase(rb);

				memcpy(buff, rb->buff, rb->len);
				sz = rb->len;
			}
			pj_mutex_unlock(stream->rbuff_mutex);

			if (rb != NULL) {  
#if 1
				//move rb to gcbuff
				pj_mutex_lock(stream->gcbuff_mutex);
				pj_list_push_back(&stream->gcbuff, rb);
				pj_mutex_unlock(stream->gcbuff_mutex);
#else
				free(rb);
				rb = NULL;
#endif
			}
			pj_mutex_unlock(call->tnl_stream_lock3);
		} else {
			sz = udt_recv(call->tnl_stream->udt_sock, (char *)buff, 2000, 0);
		}
		
		if (sz > 0)
			natnl_handle_recv_msg(call_id, call->tnl_stream->med_tp,(char *)buff, sz);
		else // UDT socket may be closed. It causes natnl_recv_thread can't work properly. Sleep 10ms .
			pj_thread_sleep(10);   
	}

	if (call->med_tp->tnl_ka_to_chk_timer.id > 0) {
		pj_timer_heap_cancel(pjsua_var[inst_id].stun_cfg.timer_heap, 
			&call->med_tp->tnl_ka_to_chk_timer);
		call->med_tp->tnl_ka_to_chk_timer.id = TIMER_NONE;
	}
	if (call->med_tp->tnl_idle_chk_timer.id > 0) {
		pj_timer_heap_cancel(pjsua_var[inst_id].stun_cfg.timer_heap, 
			&call->med_tp->tnl_idle_chk_timer);
		call->med_tp->tnl_idle_chk_timer.id = TIMER_NONE;
	}

	PJ_LOG(2, (THIS_FILE, "natnl_recv_thread terminated. call_id=[%d]", call->index));
	pj_grp_lock_dec_ref(call->tnl_stream->grp_lock);
    return 0;

THRD_TERMINATE_CALL_TUNNEL_COMPLETE:
	PJ_LOG(2, (__FILE__, "natnl_recv_thread terminated and call tunnel complete. call_id=[%d]", call->index));
	on_tunnel_complete(call, status);
	pj_grp_lock_dec_ref(call->tnl_stream->grp_lock);
	return 0;
}

static void init_data(pjsua_inst_id inst_id)
{
	unsigned i;

	pj_bzero(&pjsua_var[inst_id], sizeof(pjsua_var[inst_id]));

	pjsua_var[inst_id].id = inst_id;

	for (i=0; i<PJ_ARRAY_SIZE(pjsua_var[inst_id].acc); ++i)
		pjsua_var[inst_id].acc[i].index = i;

	for (i=0; i<PJ_ARRAY_SIZE(pjsua_var[inst_id].tpdata); ++i)
		pjsua_var[inst_id].tpdata[i].index = i;

	pjsua_var[inst_id].stun_status = PJ_EUNKNOWN;
	pjsua_var[inst_id].nat_status = PJ_EPENDING;
	pj_list_init(&pjsua_var[inst_id].stun_res);
	pj_list_init(&pjsua_var[inst_id].outbound_proxy);

	pjsua_config_default(&pjsua_var[inst_id].ua_cfg);

	// 2014-01-17 DEAN, Setup no_snd here, to avoid timing issue.
	pjsua_var[inst_id].no_snd = PJ_TRUE;
}

void pjsua_media_config_dup(pj_pool_t *pool,
				   pjsua_media_config *dst,
				   const pjsua_media_config *src)
{
    pj_memcpy(dst, src, sizeof(*src));
    pj_strdup(pool, &dst->turn_server, &src->turn_server);
    pj_stun_auth_cred_dup(pool, &dst->turn_auth_cred, &src->turn_auth_cred);
}

/**
 * Init media subsystems.
 */
pj_status_t natnl_media_subsys_init(pjsua_inst_id inst_id, const pjsua_media_config *cfg)
{
    pj_str_t codec_id = {NULL, 0};
    unsigned opt;
    pj_status_t status;

	PJ_LOG(6, (THIS_FILE, "natnl_media_subsys_init() entered."));
    /* To suppress warning about unused var when all codecs are disabled */
    PJ_UNUSED_ARG(codec_id);

    /* Specify which audio device settings are save-able */
    pjsua_var[inst_id].aud_svmask = 0xFFFFFFFF;
    /* These are not-settable */
    pjsua_var[inst_id].aud_svmask &= ~(PJMEDIA_AUD_DEV_CAP_EXT_FORMAT |
                              PJMEDIA_AUD_DEV_CAP_INPUT_SIGNAL_METER |
                              PJMEDIA_AUD_DEV_CAP_OUTPUT_SIGNAL_METER);
    /* EC settings use different API */
    pjsua_var[inst_id].aud_svmask &= ~(PJMEDIA_AUD_DEV_CAP_EC |
                              PJMEDIA_AUD_DEV_CAP_EC_TAIL);

    /* Copy configuration */
    pjsua_media_config_dup(pjsua_var[inst_id].pool, &pjsua_var[inst_id].media_cfg, cfg);

    /* Normalize configuration */
    if (pjsua_var[inst_id].media_cfg.snd_clock_rate == 0) {
        pjsua_var[inst_id].media_cfg.snd_clock_rate = pjsua_var[inst_id].media_cfg.clock_rate;
    }

    if (pjsua_var[inst_id].media_cfg.has_ioqueue &&
        pjsua_var[inst_id].media_cfg.thread_cnt == 0)
    {
        pjsua_var[inst_id].media_cfg.thread_cnt = 1;
    }

    if (pjsua_var[inst_id].media_cfg.max_media_ports < pjsua_var[inst_id].ua_cfg.max_calls) {
        pjsua_var[inst_id].media_cfg.max_media_ports = pjsua_var[inst_id].ua_cfg.max_calls + 2;
    }

	//DEAN fix bug. ioqueue doesn't get any signal about rtp media data when disable ICE.
	//pjsua_var.media_cfg.thread_cnt = 0;

    /* Create media endpoint. */
    status = pjmedia_endpt_create(&pjsua_var[inst_id].cp.factory, 
                                  pjsua_var[inst_id].media_cfg.has_ioqueue? NULL :
                                     pjsip_endpt_get_ioqueue(pjsua_var[inst_id].endpt),
                                  pjsua_var[inst_id].media_cfg.thread_cnt,
								  pjsua_var[inst_id].media_cfg.disable_sdp_compress,
								  inst_id,
                                  &pjsua_var[inst_id].med_endpt);
    if (status != PJ_SUCCESS) {
        pjsua_perror(THIS_FILE, "Media stack initialization has returned error", status);
        return status;
    }

    /* Register all codecs */
#if 0
#if PJMEDIA_HAS_G711_CODEC
    /* Register PCMA and PCMU */
    status = pjmedia_codec_g711_init(pjsua_var.med_endpt);
    if (status != PJ_SUCCESS) {
        pjsua_perror(THIS_FILE, "Error initializing G711 codec", status);
        return status;
    }
#endif        /* PJMEDIA_HAS_G711_CODEC */
#endif
	//status = pjmedia_codec_speex_init(pjsua_var.med_endpt, PJMEDIA_SPEEX_NO_UWB, 3, 3);

    /* Register ASUS proprietary NAT tunnel codec */
    status = pjmedia_codec_ntc_init(inst_id, pjsua_var[inst_id].med_endpt);
    if (status != PJ_SUCCESS) {
        pjsua_perror(THIS_FILE, "Error initializing ASUS NAT tunnel codec", status);
        return status;
    }

	pj_str_t		    tmp;
	pjsua_codec_set_priority(inst_id, pj_cstr(&tmp, "NTC/16000"), PJMEDIA_CODEC_PRIO_LOWEST);


    /* Save additional conference bridge parameters for future
     * reference.
     */
    pjsua_var[inst_id].mconf_cfg.channel_count = pjsua_var[inst_id].media_cfg.channel_count;
    pjsua_var[inst_id].mconf_cfg.bits_per_sample = 16;
    pjsua_var[inst_id].mconf_cfg.samples_per_frame = pjsua_var[inst_id].media_cfg.clock_rate * 
                                            pjsua_var[inst_id].mconf_cfg.channel_count *
                                            pjsua_var[inst_id].media_cfg.audio_frame_ptime / 
                                            1000;

    /* Init options for conference bridge. */
    opt = PJMEDIA_CONF_NO_DEVICE;
    if (pjsua_var[inst_id].media_cfg.quality >= 3 &&
        pjsua_var[inst_id].media_cfg.quality <= 4)
    {
        opt |= PJMEDIA_CONF_SMALL_FILTER;
    }
    else if (pjsua_var[inst_id].media_cfg.quality < 3) {
        opt |= PJMEDIA_CONF_USE_LINEAR;
    }
        
	PJ_LOG(5, (THIS_FILE, "call pjmedia_conf_create()."));
    /* Init conference bridge. */
    status = pjmedia_conf_create(pjsua_var[inst_id].pool, 
                                 pjsua_var[inst_id].media_cfg.max_media_ports,
                                 pjsua_var[inst_id].media_cfg.clock_rate, 
                                 pjsua_var[inst_id].mconf_cfg.channel_count,
                                 pjsua_var[inst_id].mconf_cfg.samples_per_frame, 
                                 pjsua_var[inst_id].mconf_cfg.bits_per_sample, 
                                 opt, &pjsua_var[inst_id].mconf);
	PJ_LOG(5, (THIS_FILE, "exit pjmedia_conf_create()"));
    if (status != PJ_SUCCESS) {
        pjsua_perror(THIS_FILE, "Error creating conference bridge", status);
        return status;
    }

    /* Are we using the audio switchboard (a.k.a APS-Direct)? */
    pjsua_var[inst_id].is_mswitch = pjmedia_conf_get_master_port(pjsua_var[inst_id].mconf)
                            ->info.signature == PJMEDIA_CONF_SWITCH_SIGNATURE;

#if defined(PJMEDIA_HAS_SRTP) && (PJMEDIA_HAS_SRTP != 0)
    /* Initialize SRTP library. */
    status = pjmedia_srtp_init_lib(pjsua_var[inst_id].med_endpt);
    if (status != PJ_SUCCESS) {
        pjsua_perror(THIS_FILE, "Error initializing SRTP library", status);
        return status;
    }
#endif

#if defined(PJMEDIA_HAS_DTLS) && (PJMEDIA_HAS_DTLS != 0)
	/* Initialize DTLS library. */
	status = pjmedia_dtls_init_lib(pjsua_var[inst_id].med_endpt);
	if (status != PJ_SUCCESS) {
		pjsua_perror(THIS_FILE, "Error initializing DTLS library", status);
		return status;
	}
#endif
	PJ_LOG(5, (THIS_FILE, "natnl_media_subsys_init() leaving."));

    return PJ_SUCCESS;
}

PJ_DEF(pj_status_t) natnl_logging_endpt_create(pjsua_inst_id inst_id,
											   const pjsua_logging_config *log_cfg)
{
	pj_status_t status;
	pjsip_ua_init_param  ua_init_param;
	
	if (pjsua_var[inst_id].pool)
		return PJ_SUCCESS;

	status = natnl_create(inst_id);

	if (status != PJ_SUCCESS)
		return status;

	/* Initialize logging first so that info/errors can be captured */
	if (log_cfg) {
		status = pjsua_reconfigure_logging(inst_id, log_cfg);
		if (status != PJ_SUCCESS)
			return status;
	}

	return PJ_SUCCESS;
}

PJ_DEF(pj_status_t) natnl_logging_endpt_destroy(pjsua_inst_id inst_id)
{
	//pj_status_t status = 

	return pjsua_destroy(inst_id);
}


/*
 * Instantiate natnl application.
 */
PJ_DEF(pj_status_t) natnl_create(pjsua_inst_id inst_id)
{
	pj_status_t status;

	/* Init pjsua data */
	init_data(inst_id);

    /* Set default logging settings */
    pjsua_logging_config_default(&pjsua_var[inst_id].log_cfg);

    /* Init PJLIB: */
    status = pj_init(inst_id);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    /* Init random seed */
    pj_init_random_seed();

    /* Init PJLIB-UTIL: */
    status = pjlib_util_init();
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    /* Init PJNATH */
    status = pjnath_init();
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    /* Set default sound device ID */
    pjsua_var[inst_id].cap_dev = PJMEDIA_AUD_DEFAULT_CAPTURE_DEV;
    pjsua_var[inst_id].play_dev = PJMEDIA_AUD_DEFAULT_PLAYBACK_DEV;

	//printf("factory_size=%d, cp_size=%d\n", sizeof(pj_pool_factory), sizeof(pj_caching_pool));

    /* Init caching pool. */
    pj_caching_pool_init(inst_id, &pjsua_var[inst_id].cp, NULL, 0);

    /* Create memory pool for application. */
    pjsua_var[inst_id].pool = pjsua_pool_create(inst_id, "pjsua", 1000, 1000);
    
    PJ_ASSERT_RETURN(pjsua_var[inst_id].pool, PJ_ENOMEM);

    /* Create mutex */
    status = pj_mutex_create_recursive(pjsua_var[inst_id].pool, "pjsua", 
                                       &pjsua_var[inst_id].mutex);
    if (status != PJ_SUCCESS) {
        pjsua_perror(THIS_FILE, "Unable to create mutex", status);
        return status;
    }

    /* Must create SIP endpoint to initialize SIP parser. The parser
     * is needed for example when application needs to call pjsua_verify_url().
     */
    status = pjsip_endpt_create(&pjsua_var[inst_id].cp.factory, 
                                pj_gethostname()->ptr, 
                                &pjsua_var[inst_id].endpt);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);


    return PJ_SUCCESS;
}

/*
 * Initialize pjsua with the specified settings. All the settings are 
 * optional, and the default values will be used when the config is not
 * specified.
 */
PJ_DEF(pj_status_t) natnl_init( pjsua_inst_id inst_id,
							    const pjsua_config *ua_cfg,
                                const pjsua_logging_config *log_cfg,
                                const pjsua_media_config *media_cfg)
{
    pjsua_config         default_cfg;
    pjsua_media_config   default_media_cfg;
    const pj_str_t       STR_OPTIONS = { "OPTIONS", 7 };
    pjsip_ua_init_param  ua_init_param;
    unsigned i;
    pj_status_t status;


    /* Create default configurations when the config is not supplied */

    if (ua_cfg == NULL) {
        pjsua_config_default(&default_cfg);
        ua_cfg = &default_cfg;
    }

    if (media_cfg == NULL) {
        pjsua_media_config_default(&default_media_cfg);
        media_cfg = &default_media_cfg;
    }

    /* Initialize logging first so that info/errors can be captured */
    if (log_cfg) {
        status = pjsua_reconfigure_logging(inst_id, log_cfg);
        if (status != PJ_SUCCESS)
            return status;
    }

#if defined(PJ_IPHONE_OS_HAS_MULTITASKING_SUPPORT) && \
    PJ_IPHONE_OS_HAS_MULTITASKING_SUPPORT != 0
    if (!(pj_get_sys_info()->flags & PJ_SYS_HAS_IOS_BG)) {
        PJ_LOG(5, (THIS_FILE, "Device does not support "
                              "background mode"));
        pj_activesock_enable_iphone_os_bg(PJ_FALSE);
    }
#endif

    /* If nameserver is configured, create DNS resolver instance and
     * set it to be used by SIP resolver.
     */
    if (ua_cfg->nameserver_count) {
#if PJSIP_HAS_RESOLVER
        unsigned i;

        /* Create DNS resolver */
        status = pjsip_endpt_create_resolver(pjsua_var[inst_id].endpt, 
                                             &pjsua_var[inst_id].resolver);
        if (status != PJ_SUCCESS) {
            pjsua_perror(THIS_FILE, "Error creating resolver", status);
            return status;
        }

        /* Configure nameserver for the DNS resolver */
        status = pj_dns_resolver_set_ns(pjsua_var[inst_id].resolver, 
                                        ua_cfg->nameserver_count,
                                        ua_cfg->nameserver, NULL);
        if (status != PJ_SUCCESS) {
            pjsua_perror(THIS_FILE, "Error setting nameserver", status);
            return status;
        }

        /* Set this DNS resolver to be used by the SIP resolver */
        status = pjsip_endpt_set_resolver(pjsua_var[inst_id].endpt, pjsua_var[inst_id].resolver);
        if (status != PJ_SUCCESS) {
            pjsua_perror(THIS_FILE, "Error setting DNS resolver", status);
            return status;
        }

        /* Print nameservers */
        for (i=0; i<ua_cfg->nameserver_count; ++i) {
            PJ_LOG(4,(THIS_FILE, "Nameserver %.*s added",
                      (int)ua_cfg->nameserver[i].slen,
                      ua_cfg->nameserver[i].ptr));
        }
#else
        PJ_LOG(2,(THIS_FILE, 
                  "DNS resolver is disabled (PJSIP_HAS_RESOLVER==0)"));
#endif
    }

    /* Init SIP UA: */

    /* Initialize transaction layer: */
    status = pjsip_tsx_layer_init_module(pjsua_var[inst_id].endpt);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);


    /* Initialize UA layer module: */
    pj_bzero(&ua_init_param, sizeof(ua_init_param));
    if (ua_cfg->hangup_forked_call) {
        ua_init_param.on_dlg_forked = &on_dlg_forked;
    }
    status = pjsip_ua_init_module( pjsua_var[inst_id].endpt, &ua_init_param);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

	#if 1 //disabled by Dean
    /* Initialize Replaces support. */
    status = pjsip_replaces_init_module( pjsua_var[inst_id].endpt );
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
	#endif

	#if 1 //disabled by Dean
    /* Initialize 100rel support */
    status = pjsip_100rel_init_module(pjsua_var[inst_id].endpt);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
	#endif

    /* Initialize session timer support */
    status = pjsip_timer_init_module(pjsua_var[inst_id].endpt);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);

    /* Initialize and register PJSUA application module. */
    {
        const pjsip_module mod_initializer = 
        {
        NULL, NULL,                    /* prev, next.                        */
        { "mod-pjsua", 9 },            /* Name.                                */
        -1,                            /* Id                                */
        PJSIP_MOD_PRIORITY_APPLICATION,        /* Priority                        */
        NULL,                            /* load()                                */
        NULL,                            /* start()                                */
        NULL,                            /* stop()                                */
        NULL,                            /* unload()                                */
        &mod_pjsua_on_rx_request,   /* on_rx_request()                        */
        &mod_pjsua_on_rx_response,  /* on_rx_response()                        */
        NULL,                            /* on_tx_request.                        */
        NULL,                            /* on_tx_response()                        */
        NULL,                            /* on_tsx_state()                        */
        };

        pjsua_var[inst_id].mod = mod_initializer;

        status = pjsip_endpt_register_module(pjsua_var[inst_id].endpt, &pjsua_var[inst_id].mod);
        PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
    }

    /* Parse outbound proxies */
    for (i=0; i<ua_cfg->outbound_proxy_cnt; ++i) {
        pj_str_t tmp;
                pj_str_t hname = { "Route", 5};
        pjsip_route_hdr *r;

        pj_strdup_with_null(pjsua_var[inst_id].pool, &tmp, &ua_cfg->outbound_proxy[i]);

        r = (pjsip_route_hdr*)
            pjsip_parse_hdr(inst_id, pjsua_var[inst_id].pool, &hname, tmp.ptr,
                            (unsigned)tmp.slen, NULL);
        if (r == NULL) {
            pjsua_perror(THIS_FILE, "Invalid outbound proxy URI",
                         PJSIP_EINVALIDURI);
            return PJSIP_EINVALIDURI;
        }

        if (pjsua_var[inst_id].ua_cfg.force_lr) {
            pjsip_sip_uri *sip_url;
            if (!PJSIP_URI_SCHEME_IS_SIP(r->name_addr.uri) &&
                !PJSIP_URI_SCHEME_IS_SIP(r->name_addr.uri))
            {
                return PJSIP_EINVALIDSCHEME;
            }
            sip_url = (pjsip_sip_uri*)r->name_addr.uri;
            sip_url->lr_param = 1;
        }

        pj_list_push_back(&pjsua_var[inst_id].outbound_proxy, r);
    }
    

    /* Initialize PJSUA call subsystem: */
    status = pjsua_call_subsys_init(inst_id, ua_cfg);
    if (status != PJ_SUCCESS)
        goto on_error;

    /* Convert deprecated STUN settings */
    if (pjsua_var[inst_id].ua_cfg.stun_srv_cnt==0) {
        if (pjsua_var[inst_id].ua_cfg.stun_domain.slen) {
            pjsua_var[inst_id].ua_cfg.stun_srv[pjsua_var[inst_id].ua_cfg.stun_srv_cnt++] = 
                pjsua_var[inst_id].ua_cfg.stun_domain;
        }
        if (pjsua_var[inst_id].ua_cfg.stun_host.slen) {
            pjsua_var[inst_id].ua_cfg.stun_srv[pjsua_var[inst_id].ua_cfg.stun_srv_cnt++] = 
                pjsua_var[inst_id].ua_cfg.stun_host;
        }
    }

    /* Start resolving STUN server */
    status = resolve_stun_server(inst_id, PJ_FALSE);
    if (status != PJ_SUCCESS && status != PJ_EPENDING) {
		pjsua_perror(THIS_FILE, "Error resolving STUN server", status);
		//return status; //DEAN. Ignore stun failed situation to meet UDP packet blocked environment.
    }

    /* Initialize NAT tunnel media subsystem */
    status = natnl_media_subsys_init(inst_id, media_cfg);
    if (status != PJ_SUCCESS)
        goto on_error;

    #if 0 //disabled by Andrew
    /* Init core SIMPLE module : */
    status = pjsip_evsub_init_module(pjsua_var.endpt);
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
    #endif


    #if 0 //disabled by Andrew
    /* Init presence module: */
    status = pjsip_pres_init_module( pjsua_var.endpt, pjsip_evsub_instance());
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
    #endif

    #if 0 //disabled by Andrew
    /* Initialize MWI support */
    status = pjsip_mwi_init_module(pjsua_var.endpt, pjsip_evsub_instance());
    #endif

    #if 0 //disabled by Andrew
    /* Init PUBLISH module */
    pjsip_publishc_init_module(pjsua_var.endpt);
    #endif

    /* Init xfer/REFER module */
    #if 0 //disabled by Andrew
    status = pjsip_xfer_init_module( pjsua_var.endpt );
    PJ_ASSERT_RETURN(status == PJ_SUCCESS, status);
    #endif

    #if 0 //disabled by Andrew
    /* Init pjsua presence handler: */
    status = pjsua_pres_init();
    if (status != PJ_SUCCESS)
		goto on_error;
    #endif

	#if 1 //disabled by Andrew
    /* Init out-of-dialog MESSAGE request handler. */
    status = pjsua_im_init(inst_id);
    if (status != PJ_SUCCESS)
		goto on_error;
	#endif

    #if 0 //disabled by Andrew
    /* Register OPTIONS handler */
    pjsip_endpt_register_module(pjsua_var.endpt, &pjsua_options_handler);
    #endif

    #if 1
    /* Add OPTIONS in Allow header */
    pjsip_endpt_add_capability(pjsua_var[inst_id].endpt, NULL, PJSIP_H_ALLOW,
                               NULL, 1, &STR_OPTIONS);
    #endif
    //pjsua_var[inst_id].ua_cfg.thread_cnt = 0;

    /* Start worker thread if needed. */
    if (pjsua_var[inst_id].ua_cfg.thread_cnt) {

        if (pjsua_var[inst_id].ua_cfg.thread_cnt > PJ_ARRAY_SIZE(pjsua_var[inst_id].thread))
            pjsua_var[inst_id].ua_cfg.thread_cnt = PJ_ARRAY_SIZE(pjsua_var[inst_id].thread);

            status = pj_thread_create(pjsua_var[inst_id].pool, "pjsua", &worker_thread,
                                      pjsua_var[inst_id].endpt, 0, 0, &pjsua_var[inst_id].thread[0]);
            if (status != PJ_SUCCESS)
				goto on_error;

			status = pj_thread_create(pjsua_var[inst_id].pool, "natnl_monitor", &monitor_thread,
				pjsua_var[inst_id].endpt, 0, 0, &pjsua_var[inst_id].monitor_thread[0]);
			if (status != PJ_SUCCESS)
				goto on_error;

        PJ_LOG(4,(THIS_FILE, "%d SIP worker threads created", 
                  pjsua_var[inst_id].ua_cfg.thread_cnt));
    } else {
        PJ_LOG(4,(THIS_FILE, "No SIP worker threads created"));
    }

	status = im_init(inst_id);
	if (status != PJ_SUCCESS)
		goto on_error;

	udt_startup(inst_id);
#if !defined(PJMEDIA_DISABLE_SCTP) || (PJMEDIA_DISABLE_SCTP == 0)
	init_usrsctp(NULL);
	{
		const pj_str_t sctp_tag = { "SCTP", 4 };

		/* Register SCTP support. */
		pjsip_endpt_add_capability( pjsua_var[inst_id].endpt, NULL, PJSIP_H_TNL_SUPPORTED,
			NULL, 1, &sctp_tag);

	}
#endif

    /* Done! */

    PJ_LOG(3,(THIS_FILE, "pjsua version %s for %s initialized", 
                         pj_get_version(), pj_get_sys_info()->info.ptr));

    return PJ_SUCCESS;

on_error:
    pjsua_destroy(inst_id);
    return status;
}

pjsua_call *pjsua_get_call(pjsua_inst_id inst_id, pjsua_call_id call_id)
{
	return &pjsua_var[inst_id].calls[call_id];
}

pjmedia_transport *pjsua_get_media_transport(pjsua_inst_id inst_id, pjsua_call_id call_id)
{
	return pjsua_var[inst_id].calls[call_id].med_tp;
}

PJ_DEF(void) natnl_call_callback(struct natnl_tnl_event *tnl_event)
{
	natnl_call_callback2(tnl_event, 1);
}

PJ_DEF(void) natnl_call_callback2(struct natnl_tnl_event *tnl_event, int use_pj_log)
{
	char *ua_type;
	char *nat_type;
	char *tnl_type;
	char upnp_port[200] = {0};
	int i;
	pj_timestamp time1, time2;
	unsigned long thrd_id = 0;

	//strcpy(tnl_event->para.local_info.version, natnl_get_version());

	if (tnl_event->nat_type == 0)
		nat_type = "UNKNOWN";
	else if (tnl_event->nat_type == 1)
		nat_type = "ERR_UNKNOWN";
	else if (tnl_event->nat_type == 2)
		nat_type = "OPEN";
	else if (tnl_event->nat_type == 3)
		nat_type = "BLOCKED";
	else if (tnl_event->nat_type == 4)
		nat_type = "SYMMETRIC_UDP";
	else if (tnl_event->nat_type == 5)
		nat_type = "FULL_CONE";
	else if (tnl_event->nat_type == 6)
		nat_type = "SYMMETRIC";
	else if (tnl_event->nat_type == 7)
		nat_type = "RESTRICTED";
	else if (tnl_event->nat_type == 8)
		nat_type = "PORT RESTRICTED";
	else
		nat_type = "UNKNOWND";

	if (tnl_event->ua_type == 0)
		ua_type = "UNKNOWN";
	else if (tnl_event->ua_type == 1)
		ua_type = "UAC";
	else if (tnl_event->ua_type == 2)
		ua_type = "UAS";
	else
		ua_type = "UNKNOWND";

	if (tnl_event->tnl_type == 0)
		tnl_type = "UNKNOWN";
	else if (tnl_event->tnl_type == 1)
		tnl_type = "TCP";
	else if (tnl_event->tnl_type == 2)
		tnl_type = "TURN";
	else if (tnl_event->tnl_type == 3)
		tnl_type = "UDP";
	else
		tnl_type = "UNKNOWND";

	for (i = 0; i < sizeof(tnl_event->upnp_port)/sizeof(tnl_event->upnp_port[0]); i++)
	{
		char port[8];
		sprintf(port, "[%d]", tnl_event->upnp_port[i]);
		strcat(upnp_port, port);
	}

	if (tnl_event->inst_id >= 1 &&
		tnl_event->event_code != NATNL_TNL_EVENT_DEINIT_FAILED &&
		tnl_event->event_code != NATNL_TNL_EVENT_DEINIT_OK && 
		pjsua_var[tnl_event->inst_id].mutex)
	{
		PJ_LOG(4, ("natnl.c", "inst_id=%d", tnl_event->inst_id));
		thrd_id = pj_gettid();
	}

	if (tnl_event->inst_id >= 1) {
		//tnl_event->app_data = natnl_get_app_data(tnl_event->inst_id);
		PJ_LOG(4, ("natnl.c", "%s", (char *)tnl_event->app_data));
	}

	if (strlen(tnl_event->status_text) == 0) {
		pj_strerror(tnl_event->status_code, tnl_event->status_text, sizeof(tnl_event->status_text));
	}

	if (use_pj_log)
		PJ_LOG(4, ("natnl.c", " \n >>>>>>>>>natnl_call_callback [%p][tid=%d] \n >>inst_id=%d, \n >>call_id=%d, "
		"\n >>event_code=%d, \n >>event_text=%s, \n >>status_code=%d, \n >>status_text=%s, "
		"\n >>session_id=%s, \n >>ua_type=%s, \n >>nat_type=%s, \n >>tnl_type=%s, \n >>local_ua_version=%s, "
		"\n >>remote_device_id=%s, \n >>remote_user_id=%s, \n >>remote_ua_varesion=%s, "
		"\n >>local_ip=%s, \n >>public_ip=%s, \n >>upnp_port=%s, \n >>mac_address=%s, \n >>app_data=%p, "
		"\n >>turn_mapped_address=%s, \n >>ice_retry=%d, \n >>dtls_retry=%d, \n >>udt_retry=%d, \n >>sctp_retry=%d, "
		"\n >>stun_last_status=%d, \n >>stun_status_text=%s, \n >>turn_last_status=%d, \n >>turn_status_text=%s, "
		"\n >>tnl_build_spent_sec=%d, \n >>natnl_call_callback [%p][tid=%d]<<<<<<<<<", 
		natnl_callback.on_natnl_tnl_event,
		thrd_id,
		tnl_event->inst_id,
		tnl_event->call_id,
		tnl_event->event_code,
		tnl_event->event_text,
		tnl_event->status_code,
		tnl_event->status_text,
		tnl_event->session_id,
		ua_type,
		nat_type,
		tnl_type,
		tnl_event->para.local_info.version,
		tnl_event->para.remote_info.device_id,
		tnl_event->para.remote_info.user_id,
		tnl_event->para.remote_info.version,
		tnl_event->local_ip,
		tnl_event->public_ip,
		upnp_port,
		tnl_event->mac_address,
		tnl_event->app_data,
		tnl_event->turn_mapped_address,
		tnl_event->retry_count.ice,
		tnl_event->retry_count.dtls,
		tnl_event->retry_count.udt,
		tnl_event->retry_count.sctp,
		tnl_event->stun_last_status,
		tnl_event->stun_status_text,
		tnl_event->turn_last_status,
		tnl_event->turn_status_text,
		tnl_event->tnl_build_spent_sec,
		natnl_callback.on_natnl_tnl_event,
		thrd_id));
	else
		/*printf("natnl.c \n >>>>>>>>>natnl_call_callback [%p][tid=%d] \n >>inst_id=%d, \n >>call_id=%d, "
		"\n >>event_code=%d, \n >>event_text=%s, \n >>status_code=%d, \n >>status_text=%s, "
		"\n >>session_id=%s, \n >>ua_type=%s, \n >>nat_type=%s, \n >>tnl_type=%s, \n >>local_ua_version=%s, "
		"\n >>remote_device_id=%s, \n >>remote_user_id=%s, \n >>remote_ua_varesion=%s, "
		"\n >>local_ip=%s, \n >>public_ip=%s, \n >>upnp_port=%s, \n >>mac_address=%s, \n >>app_data=%p, "
		"\n >>turn_mapped_address=%s, \n natnl_call_callback [%p][tid=%d]<<<<<<<<<", 
		natnl_callback.on_natnl_tnl_event,
		thrd_id,
		tnl_event->inst_id,
		tnl_event->call_id,
		tnl_event->event_code,
		tnl_event->event_text,
		tnl_event->status_code,
		tnl_event->status_text,
		tnl_event->session_id,
		ua_type,
		nat_type,
		tnl_type,
		tnl_event->para.local_info.version,
		tnl_event->para.remote_info.device_id,
		tnl_event->para.remote_info.user_id,
		tnl_event->para.remote_info.version,
		tnl_event->local_ip,
		tnl_event->public_ip,
		upnp_port,
		tnl_event->mac_address,
		tnl_event->app_data,
		tnl_event->turn_mapped_address,
		natnl_callback.on_natnl_tnl_event,
		thrd_id)*/;

	if (natnl_callback.on_natnl_tnl_event) 
	{
		int elapsed_time;
		pj_get_timestamp(&time1);
		natnl_callback.on_natnl_tnl_event(tnl_event);
		pj_get_timestamp(&time2);
		PJ_LOG(4, ("natnl.c", ">>>>>>>>> callback consume %d ms.", 
			elapsed_time = pj_elapsed_msec(&time1, &time2)));
	}
}


