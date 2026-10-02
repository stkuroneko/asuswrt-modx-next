/*
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 * 
 */

int
wmi_unified_vdev_start_send(wmi_unified_t wmi_handle, u_int8_t if_id, struct ieee80211_channel *chan, u_int32_t freq, bool disable_hw_ack, void *nl_handle);
int
wmi_unified_vdev_restart_send(wmi_unified_t wmi_handle, u_int8_t if_id, struct ieee80211_channel *chan, u_int32_t freq, bool disable_hw_ack);

