/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This file contains the API definitions for the Unified Wireless Module Interface (WMI).
 */

#ifndef _WMI_UNIFIED_API_H_
#define _WMI_UNIFIED_API_H_

#include <osdep.h>
#include <wbuf.h>
#include "a_types.h"
#include "ol_defines.h"
#include "wmi.h"
#include "ol_if_ath_api.h"
#include "htc_api.h"

/**
 * NOTE: for now wmi_buf is mapped to wbuf
 */
typedef wbuf_t wmi_buf_t;
#define wmi_buf_free(_buf) wbuf_free(_buf)
#define wmi_buf_data(_buf) wbuf_header(_buf)

/**
 * attach for unified WMI
 *
 *  @param scn_handle      : handle to SCN.
 *  @return opaque handle.
 */
void *
wmi_unified_attach(void *scn_handle, osdev_t osdev);
/**
 * detach for unified WMI
 *
 *  @param wmi_handle      : handle to WMI.
 *  @return void.
 */
void
wmi_unified_detach(struct wmi_unified* wmi_handle);

/**
 * generic function to allocate WMI buffer
 *
 *  @param wmi_handle      : handle to WMI.
 *  @param len             : length of the buffer
 *  @return wmi_buf_t.
 */
wmi_buf_t
wmi_buf_alloc(wmi_unified_t wmi_handle, int len);


/**
 * generic function to send unified WMI command
 *
 *  @param wmi_handle      : handle to WMI.
 *  @param buf             : wmi command buffer
 *  @param buflen          : wmi command buffer length
 *  @return 0  on success and -ve on failure.
 */
int
wmi_unified_cmd_send(wmi_unified_t wmi_handle, void *buf, int buflen, WMI_CMD_ID cmd_id);

/**
 *  generic function to block unified WMI command
 *  @param wmi_handle      : handle to WMI.
 *  @return 0  on success and -ve on failure.
 */
int
wmi_stop(wmi_unified_t wmi_handle);

/**
 *  API to flush all the previous packets  associated with the wmi endpoint
 *
 *  @param wmi_handle      : handle to WMI.
 */
void
wmi_flush_endpoint(wmi_unified_t wmi_handle);


/**
 * WMI event handler register function
 *
 *  @param wmi_handle      : handle to WMI.
 *  @param event_id        : WMI event ID
 *  @param handler_func    : Event handler call back function
 *  @param cookie          : cookie registered with call back function
 *  @return 0  on success and -ve on failure.
 */
int
wmi_unified_register_event_handler(wmi_unified_t wmi_handle, WMI_EVT_ID event_id,
                                   wmi_unified_event_handler handler_func,
                                   void* cookie);

/**
 * WMI event handler unregister function
 *
 *  @param wmi_handle      : handle to WMI.
 *  @param event_id        : WMI event ID
 *  @return 0  on success and -ve on failure.
 */
int
wmi_unified_unregister_event_handler(wmi_unified_t wmi_handle, WMI_EVT_ID event_id);


/**
 * request wmi to connet its htc service.
 *  @param wmi_handle      : handle to WMI.
 *  @return void
 */
int
wmi_unified_connect_htc_service(struct wmi_unified * wmi_handle, void *htc_handle);

/**
 * generic function to get the scn handle
 *
 *  @param wmi_handle      : handle to WMI.
 *  @return ol_scn_t.
 */
ol_scn_t
wmi_get_scn_handle(wmi_unified_t wmi_handle);

#if WMI_RECORDING
void wmi_add_to_circ(wmi_unified_t wmi_handle, char *cmd, int len, WMI_CMD_ID id);
void wmi_proc_create(wmi_unified_t wmi_handle, struct proc_dir_entry *entry, int id);
void wmi_proc_remove(wmi_unified_t wmi_handle, struct proc_dir_entry *entry, int id);
#endif

#endif /* _WMI_UNIFIED_API_H_ */
