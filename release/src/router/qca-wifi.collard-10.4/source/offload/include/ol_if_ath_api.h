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
 * Defintions for the Atheros Wireless LAN controller driver.
 */
#ifndef _DEV_OL_ATH_API_H
#define _DEV_OL_ATH_API_H

#include <osdep.h>
#include "ol_defines.h"
#include "wbuf.h"
#include "htc_api.h"
#include "wmi.h"

A_STATUS ol_ath_send(ol_scn_t scn, wbuf_t wbuf, HTC_ENDPOINT_ID eid);
void
ol_ath_ready_event(ol_scn_t scn_handle, wmi_ready_event *ev);
void
ol_ath_service_ready_event(ol_scn_t scn_handle, wmi_service_ready_event *ev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
int
create_queue_work(ol_scn_t scn_handle, void *buf);
#endif

#endif /* _DEV_OL_ATH_API_H  */
