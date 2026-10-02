/*
 * Copyright (c) 2011-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
/**
 * @file ol_txrx_ctrl_api.h
 * @brief Define the host data API functions called by the host control SW.
 */
#ifndef _OL_TXRX_CTRL_API__H_
#define _OL_TXRX_CTRL_API__H_

#include <athdefs.h>      /* A_STATUS */
#include <adf_nbuf.h>     /* adf_nbuf_t */
#include <adf_os_types.h> /* adf_os_device_t */
#include <htc_api.h>      /* HTC_HANDLE */
#include <htt.h>

#include <ol_osif_api.h> /* ol_osif_vdev_handle */
#include <ol_txrx_api.h> /* ol_txrx_pdev_handle, etc. */
#include <ol_ctrl_api.h> /* ol_pdev_handle, ol_vdev_handle */

#include <wlan_defs.h>   /* MAX_SPATIAL_STREAM */
#include <htt.h>

/**
 * @brief Set up the data SW subsystem.
 * @details
 *  As part of the WLAN device attach, the data SW subsystem has
 *  to be attached as a component within the WLAN device.
 *  This attach allocates and initializes the physical device object
 *  used by the data SW.
 *  The data SW subsystem attach needs to happen after the target has
 *  be started, and host / target parameter negotiation has completed,
 *  since the host data SW uses some of these host/target negotiated
 *  parameters (e.g. peer ID range) during the initializations within
 *  its attach function.
 *  However, the host data SW is not allowed to send HTC messages to the
 *  target within this pdev_attach function call, since the HTC setup
 *  has not complete at this stage of initializations.  Any messaging
 *  to the target has to be done in the separate pdev_attach_target call
 *  that is invoked after HTC setup is complete.
 *
 * @param ctrl_pdev - control SW's physical device handle, needed as an
 *      argument for dynamic configuration queries
 * @param htc_pdev - the HTC physical device handle.  This is not needed
 *      by the txrx module, but needs to be passed along to the HTT module.
 * @param osdev - OS handle needed as an argument for some OS primitives
 * @return the data physical device object
 */
ol_txrx_pdev_handle
ol_txrx_pdev_attach(
    ol_pdev_handle ctrl_pdev,
    HTC_HANDLE htc_pdev,
    adf_os_device_t osdev);

/**
 * @brief Do final steps of data SW setup that send messages to the target.
 * @details
 *  The majority of the data SW setup are done by the pdev_attach function,
 *  but this function completes the data SW setup by sending datapath
 *  configuration messages to the target.
 *
 * @param data_pdev - the physical device being initialized
 */
A_STATUS
ol_txrx_pdev_attach_target(ol_txrx_pdev_handle data_pdev);

int
ol_txrx_mempools_attach(ol_pdev_handle ctrl_pdev);
/**
 * @brief Wrapper for rate-control context initialization
 * @details
 *  Enables the switch that controls the allocation of the
 *  rate-control contexts on the host.
 *
 * @param pdev   - the physical device being initialized
 * @param enable - 1: enabled 0: disabled
 */
void ol_txrx_enable_host_ratectrl(ol_txrx_pdev_handle pdev, u_int32_t enable);


/**
 * @brief modes that a virtual device can operate as
 * @details
 *  A virtual device can operate as an AP, an IBSS, or a STA (client).
 *  or in monitor mode
 */
enum wlan_op_mode {
   wlan_op_mode_unknown,
   wlan_op_mode_ap,
   wlan_op_mode_ibss,
   wlan_op_mode_sta,
   wlan_op_mode_monitor,
};


/**
 * @brief Allocate and initialize the data object for a new virtual device.
 * @param data_pdev - the physical device the virtual device belongs to
 * @param vdev_mac_addr - the MAC address of the virtual device
 * @param vdev_id - the ID used to identify the virtual device to the target
 * @param op_mode - whether this virtual device is operating as an AP,
 *      an IBSS, or a STA
 * @return
 *      success: handle to new data vdev object, -OR-
 *      failure: NULL
 */
ol_txrx_vdev_handle
ol_txrx_vdev_attach(
    ol_txrx_pdev_handle data_pdev,
    u_int8_t *vdev_mac_addr,
    u_int8_t vdev_id,
    enum wlan_op_mode op_mode);

/**
 * @brief Allocate and set up references for a data peer object.
 * @details
 *  When an association with a peer starts, the host's control SW
 *  uses this function to inform the host data SW.
 *  The host data SW allocates its own peer object, and stores a
 *  reference to the control peer object within the data peer object.
 *  The host data SW also stores a reference to the virtual device
 *  that the peer is associated with.  This virtual device handle is
 *  used when the data SW delivers rx data frames to the OS shim layer.
 *  The host data SW returns a handle to the new peer data object,
 *  so a reference within the control peer object can be set to the
 *  data peer object.
 *
 * @param data_pdev - data physical device object that will indirectly
 *      own the data_peer object
 * @param data_vdev - data virtual device object that will directly
 *      own the data_peer object
 * @param peer_mac_addr - MAC address of the new peer
 * @return handle to new data peer object, or NULL if the attach fails
 */
ol_txrx_peer_handle
ol_txrx_peer_attach(
    ol_txrx_pdev_handle data_pdev,
    ol_txrx_vdev_handle data_vdev,
    u_int8_t *peer_mac_addr);

/**
 * @brief Template for passing ieee80211_node members to rate-control
 * @details
 *  This structure is used in order to maintain the isolation between umac and
 *  ol while initializing the peer-level rate-control context with peer-specific
 *  parameters.
 */
struct peer_ratectrl_params_t {
    u_int8_t ni_streams;
    u_int8_t is_auth_wpa;
    u_int8_t is_auth_wpa2;
    u_int8_t is_auth_8021x;
    u_int32_t ni_flags;
    u_int32_t ni_chwidth;
    u_int16_t ni_htcap;
    u_int16_t ni_vhtcap;
    u_int16_t ni_phymode;
    u_int16_t ni_rx_vhtrates;
    u_int8_t ht_rates[MAX_SPATIAL_STREAM * 8];
};

/**
 * @brief Update the authorize peer object at association time
 * @details
 *  For the host-based implementation of rate-control, it
 *  updates the peer/node-related parameters within rate-control
 *  context of the peer at association.
 *
 * @param peer - pointer to the node's object
 * @authorize - either to authorize or unauthorize peer
 *
 * @return none
 */
void
ol_txrx_peer_authorize(struct ol_txrx_peer_t *peer, u_int32_t authorize);

/**
 * @brief Update the data peer object at association time
 * @details
 *  For the host-based implementation of rate-control, it
 *  updates the peer/node-related parameters within rate-control
 *  context of the peer at association.
 *
 * @param peer - pointer to the node's object
 * @param peer_ratectrl_params - peer params in peer-level ratecontrol context
 *
 * @return none
 */
void
ol_txrx_peer_update(struct ol_txrx_peer_t *peer,
        struct peer_ratectrl_params_t *peer_ratectrl_params);

/**
 * @brief Notify tx data SW that a peer's transmissions are suspended.
 * @details
 *  This function applies only to HL systems - in LL systems, tx flow control
 *  is handled entirely within the target FW.
 *  The HL host tx data SW is doing tx classification and tx download
 *  scheduling, and therefore also needs to actively participate in tx
 *  flow control.  Specifically, the HL tx data SW needs to check whether a
 *  given peer is available to transmit to, or is paused.
 *  This function is used to tell the HL tx data SW when a peer is paused,
 *  so the host tx data SW can hold the tx frames for that SW.
 *
 * @param data_peer - which peer is being paused
 */
void
ol_txrx_peer_pause(ol_txrx_peer_handle data_peer);

/**
 * @brief Notify tx data SW that a peer-TID is ready to transmit to.
 * @details
 *  This function applies only to HL systems - in LL systems, tx flow control
 *  is handled entirely within the target FW.
 *  If a peer-TID has tx paused, then the tx datapath will end up queuing
 *  any tx frames that arrive from the OS shim for that peer-TID.
 *  In a HL system, the host tx data SW itself will classify the tx frame,
 *  and determine that it needs to be queued rather than downloaded to the
 *  target for transmission.
 *  Once the peer-TID is ready to accept data, the host control SW will call
 *  this function to notify the host data SW that the queued frames can be
 *  enabled for transmission, or specifically to download the tx frames
 *  to the target to transmit.
 *  The TID parameter is an extended version of the QoS TID.  Values 0-15
 *  indicate a regular QoS TID, and the value 16 indicates either non-QoS
 *  data, multicast data, or broadcast data.
 *
 * @param data_peer - which peer is being unpaused
 * @param tid - which TID within the peer is being unpaused, or -1 as a
 *      wildcard to unpause all TIDs within the peer
 */
void
ol_txrx_peer_tid_unpause(ol_txrx_peer_handle data_peer, int tid);

/**
 * @brief Tell a paused peer to release a specified number of tx frames.
 * @details
 *  This function applies only to HL systems - in LL systems, tx flow control
 *  is handled entirely within the target FW.
 *  Download up to a specified maximum number of tx frames from the tx
 *  queues of the specified TIDs within the specified paused peer, usually
 *  in response to a U-APSD trigger from the peer.
 *  It is up to the host data SW to determine how to choose frames from the
 *  tx queues of the specified TIDs.  However, the host data SW does need to
 *  provide long-term fairness across the U-APSD enabled TIDs.
 *  The host data SW will notify the target data FW when it is done downloading
 *  the batch of U-APSD triggered tx frames, so the target data FW can
 *  differentiate between an in-progress download versus a case when there are
 *  fewer tx frames available than the specified limit.
 *  This function is relevant primarily to HL U-APSD, where the frames are
 *  held in the host.
 *
 * @param peer - which peer sent the U-APSD trigger
 * @param tid_mask - bitmask of U-APSD enabled TIDs from whose tx queues
 *      tx frames can be released
 * @param max_frms - limit on the number of tx frames to release from the
 *      specified TID's queues within the specified peer
 */
void
ol_txrx_tx_release(
    ol_txrx_peer_handle peer,
    u_int32_t tid_mask,
    int max_frms);

/**
 * @brief Suspend all tx data for the specified virtual device.
 * @details
 *  This function applies only to HL systems - in LL systems, tx flow control
 *  is handled entirely within the target FW.
 *  As an example, this function could be used when a single-channel physical
 *  device supports multiple channels by jumping back and forth between the
 *  channels in a time-shared manner.  As the device is switched from channel
 *  A to channel B, the virtual devices that operate on channel A will be
 *  paused.
 *
 * @param data_vdev - the virtual device being paused
 */
void
ol_txrx_vdev_pause(ol_txrx_vdev_handle data_vdev);

/**
 * @brief Resume tx for the specified virtual device.
 * @details
 *  This function applies only to HL systems - in LL systems, tx flow control
 *  is handled entirely within the target FW.
 *
 * @param data_vdev - the virtual device being unpaused
 */
void
ol_txrx_vdev_unpause(ol_txrx_vdev_handle data_vdev);

/**
 * @brief Suspend all tx data for the specified physical device.
 * @details
 *  This function applies only to HL systems - in LL systems, tx flow control
 *  is handled entirely within the target FW.
 *  In some systems it is necessary to be able to temporarily
 *  suspend all WLAN traffic, e.g. to allow another device such as bluetooth
 *  to temporarily have exclusive access to shared RF chain resources.
 *  This function suspends tx traffic within the specified physical device.
 * 
 * @param data_pdev - the physical device being paused
 */
void
ol_txrx_pdev_pause(ol_txrx_pdev_handle data_pdev);

/**
 * @brief Resume tx for the specified physical device.
 * @details
 *  This function applies only to HL systems - in LL systems, tx flow control
 *  is handled entirely within the target FW.
 *
 * @param data_pdev - the physical device being unpaused
 */
void
ol_txrx_pdev_unpause(ol_txrx_pdev_handle data_pdev);

/**
 * @brief Synchronize the data-path tx with a control-path target download
 * @dtails
 * @param data_pdev - the data-path physical device object
 * @param sync_cnt - after the host data-path SW downloads this sync request
 *      to the target data-path FW, the target tx data-path will hold itself
 *      in suspension until it is given an out-of-band sync counter value that
 *      is equal to or greater than this counter value
 */
void
ol_txrx_tx_sync(ol_txrx_pdev_handle data_pdev, u_int8_t sync_cnt);

/**
 * @brief Delete a peer's data object.
 * @details
 *  When the host's control SW disassociates a peer, it calls this
 *  function to delete the peer's data object.
 *  The reference stored in the control peer object to the data peer
 *  object (set up by a call to ol_peer_store()) is provided.
 *
 * @param data_peer - the object to delete
 */
void
ol_txrx_peer_detach(ol_txrx_peer_handle data_peer);

typedef void (*ol_txrx_vdev_delete_cb)(void *context);

/**
 * @brief Deallocate the specified data virtual device object.
 * @details
 *  All peers associated with the virtual device need to be deleted
 *  (ol_txrx_peer_detach) before the virtual device itself is deleted.
 *  However, for the peers to be fully deleted, the peer deletion has to
 *  percolate through the target data FW and back up to the host data SW.
 *  Thus, even though the host control SW may have issued a peer_detach
 *  call for each of the vdev's peers, the peer objects may still be
 *  allocated, pending removal of all references to them by the target FW.
 *  In this case, though the vdev_detach function call will still return
 *  immediately, the vdev itself won't actually be deleted, until the
 *  deletions of all its peers complete.
 *  The caller can provide a callback function pointer to be notified when
 *  the vdev deletion actually happens - whether it's directly within the
 *  vdev_detach call, or if it's deferred until all in-progress peer
 *  deletions have completed.
 *
 * @param data_vdev - data object for the virtual device in question
 * @param callback - function to call (if non-NULL) once the vdev has
 *      been wholly deleted
 * @param callback_context - context to provide in the callback
 */
void
ol_txrx_vdev_detach(
    ol_txrx_vdev_handle data_vdev,
    ol_txrx_vdev_delete_cb callback,
    void *callback_context);

/**
 * @brief Delete the data SW state.
 * @details
 *  This function is used when the WLAN driver is being removed to
 *  remove the host data component within the driver.
 *  All virtual devices within the physical device need to be deleted
 *  (ol_txrx_vdev_detach) before the physical device itself is deleted.
 *
 * @param data_pdev - the data physical device object being removed
 * @param force - delete the pdev (and its vdevs and peers) even if there
 *      are outstanding references by the target to the vdevs and peers
 *      within the pdev
 */
void
ol_txrx_pdev_detach(ol_txrx_pdev_handle data_pdev, int force);


typedef void
(*ol_txrx_mgmt_tx_cb)(void *ctxt, adf_nbuf_t tx_mgmt_frm, int had_error);

/**
 * @brief Store a callback for delivery notifications for managements frames.
 * @details
 *  When the txrx SW receives notifications from the target that a tx frame
 *  has been delivered to its recipient, it will check if the tx frame
 *  is a management frame.  If so, the txrx SW will check the management
 *  frame type specified when the frame was submitted for transmission.
 *  If there is a callback function registered for the type of managment
 *  frame in question, the txrx code will invoke the callback to inform
 *  the management + control SW that the mgmt frame was delivered.
 *  This function is used by the control SW to store a callback pointer
 *  for a given type of management frame.
 *
 * @param pdev - the data physical device object
 * @param type - the type of mgmt frame the callback is used for
 * @param cb - the callback for delivery notification 
 * @param ctxt - context to use with the callback
 */
void
ol_txrx_mgmt_tx_cb_set(
    ol_txrx_pdev_handle pdev,
    u_int8_t type,
    ol_txrx_mgmt_tx_cb cb,
    void *ctxt);

/**
 * @brief Transmit a management frame.
 * @details
 *  Send the specified management frame from the specified virtual device.
 *  The type is used for determining whether to invoke a callback to inform
 *  the sender that the tx mgmt frame was delivered, and if so, which
 *  callback to use.
 *
 * @param vdev - virtual device transmitting the frame
 * @param tx_mgmt_frm - management frame to transmit
 * @param type - the type of managment frame (determines what callback to use)
 * @return
 *      0 -> the frame is accepted for transmission, -OR-
 *      1 -> the frame was not accepted
 */
int
ol_txrx_mgmt_send(
    ol_txrx_vdev_handle vdev,
    adf_nbuf_t tx_mgmt_frm,
    u_int8_t type);

/**
 * @brief Setup the monitor mode vap (vdev) for this pdev
 * @details
 *  When a non-NULL vdev handle is registered as the monitor mode vdev, all
 *  packets received by the system are delivered to the OS stack on this
 *  interface in 802.11 MPDU format. Only a single monitor mode interface
 *  can be up at any timer. When the vdev handle is set to NULL the monitor
 *  mode delivery is stopped. This handle may either be a unique vdev
 *  object that only receives monitor mode packets OR a point to a a vdev
 *  object that also receives non-monitor traffic. In the second case the
 *  OS stack is responsible for delivering the two streams using approprate
 *  OS APIs 
 *
 * @param pdev - the data physical device object
 * @param vdev - the data virtual device object to deliver monitor mode
 *                  packets on
 * @return
 *       0 -> the monitor mode vap was sucessfully setup
 *      -1 -> Unable to setup monitor mode
 */
int
ol_txrx_set_monitor_mode_vap(
    ol_txrx_pdev_handle pdev,
    ol_txrx_vdev_handle vdev);

int
ol_txrx_set_monitor_data_filter(
    ol_txrx_pdev_handle pdev,
    u_int32_t val);

int
ol_txrx_set_filter_neighbour_peers(
    ol_txrx_pdev_handle pdev,
    u_int32_t val);
/**
 * @brief Setup the current operating channel of the device 
 * @details
 *  Mainly used when populating monitor mode status that requires the
 *  current operating channel 
 *
 * @param pdev - the data physical device object
 * @param chan_mhz - the channel frequency (mhz)
 *                  packets on
 * @return - void
 */
void
ol_txrx_set_curchan(
    ol_txrx_pdev_handle pdev,
    u_int32_t chan_mhz);

/**
 * @brief Get the number of pending transmit frames that are awaiting completion.
 * @details
 *  Mainly used in clean up path to make sure all buffers have been free'ed
 *
 * @param pdev - the data physical device object
 * @return - count of pending frames
 */
int
ol_txrx_get_tx_pending(
    ol_txrx_pdev_handle pdev);

/**
 * @brief set the safemode of the device
 * @details
 *  This flag is used to bypass the encrypt and decrypt processes when send and 
 *  receive packets. It works like open AUTH mode, HW will treate all packets 
 *  as non-encrypt frames because no key installed. For rx fragmented frames,
 *  it bypasses all the rx defragmentaion.
 *
 * @param vdev - the data virtual device object
 * @param val - the safemode state
 * @return - void
 */
void 
ol_txrx_set_safemode(
    ol_txrx_vdev_handle vdev,
    u_int32_t val);

/**
 * @brief set the Tx encapsulation type of the VDEV
 * @details
 *  This will be used to populate the HTT desc packet type field during Tx
 *
 * @param vdev - the data virtual device object
 * @param val - the Tx encap type
 * @return - void
 */
void
ol_txrx_set_tx_encap_type(
    ol_txrx_vdev_handle vdev,
    enum htt_pkt_type val);

/**
 * @brief get the Tx encapsulation type of the VDEV
 *
 * @param vdev - the data virtual device object
 * @return - the Tx encap type
 */
enum htt_pkt_type
ol_txrx_get_tx_encap_type(ol_txrx_vdev_handle vdev);

/**
 * @brief set the Rx decapsulation type of the VDEV
 * @details
 *  This will be used to configure into firmware and hardware which format to
 *  decap all Rx packets into, for all peers under the VDEV.
 * 
 * @param vdev - the data virtual device object
 * @param val - the Rx decap mode
 * @return - void
 */
void
ol_txrx_set_vdev_rx_decap_type(
        ol_txrx_vdev_handle vdev,
        enum htt_pkt_type val);

/**
 * @brief get the Rx decapsulation type of the VDEV
 * 
 * @param vdev - the data virtual device object
 * @return - the Rx decap type
 */
enum htt_pkt_type
ol_txrx_get_vdev_rx_decap_type(ol_txrx_vdev_handle vdev);

/**
 * @brief set the privacy filter
 * @details
 *  Rx related. Set the privacy filters. When rx packets, check the ether type, filter type and
 *  packet type to decide whether discard these packets.
 *
 * @param vdev - the data virtual device object
 * @param filter - filters to be set
 * @param num - the number of filters
 * @return - void
 */
void
ol_txrx_set_privacy_filters(
    ol_txrx_vdev_handle vdev, 
	void *filter,
    u_int32_t num);

/**
 * @brief configure the drop unencrypted frame flag
 * @details
 *  Rx related. When set this flag, all the unencrypted frames
 *  received over a secure connection will be discarded
 * 
 * @param vdev - the data virtual device object
 * @param val - flag
 * @return - void
 */
void
ol_txrx_set_drop_unenc(
    ol_txrx_vdev_handle vdev,
    u_int32_t val);

#if WDS_VENDOR_EXTENSION
/**
 *  @brief Update the data peer object at association time with wds tx policy
 *  @details
 *  update the wds tx policy of peer/node at association.
 * 
 *  @param peer - pointer to the node's object
 *  @param wds_tx_policy bit mask - 0 - disable wds vendor extension tx policy
 *                                 b1 - use 4-addr ucast frames
 *                                 b2 - use 4-addr mcast frames
 *
 *  @return none
 */

void
ol_txrx_peer_wds_tx_policy_update(
    struct ol_txrx_peer_t *peer, 
    int wds_tx_policy_ucast, 
    int wds_tx_policy_mcast);

/**
 * @brief set the wds rx filter policy of the device
 * @details
 *  This flag sets the wds rx policy on the vdev. Rx frames not compliant
 *  with the policy will be dropped. 
 *
 * @param vdev - the data virtual device object
 * @param val - the wds rx policy bitmask
 * @return - void
 */
void 
ol_txrx_set_wds_rx_policy(
    ol_txrx_vdev_handle vdev,
    u_int32_t val);
#endif
/**
 * @brief set the privacy filter
 * @details
 *  Rx related. Set the privacy filters. When rx packets, check the ether type, filter type and
 *  packet type to decide whether discard these packets.
 *
 * @param vdev - the data virtual device object
 * @param filter - filters to be set
 * @param num - the number of filters
 * @return - void
 */
void
ol_txrx_set_privacy_filters(
    ol_txrx_vdev_handle vdev, 
	void *filter,
    u_int32_t num);

/**
 * @brief configure the drop unencrypted frame flag
 * @details
 *  Rx related. When set this flag, all the unencrypted frames
 *  received over a secure connection will be discarded
 * 
 * @param vdev - the data virtual device object
 * @param val - flag
 * @return - void
 */
void
ol_txrx_set_drop_unenc(
    ol_txrx_vdev_handle vdev,
    u_int32_t val);

/**
 * @brief Enable enhanced stats functionality.
 * 
 * @param pdev - the physical device object
 * @return - void
 */
void
ol_txrx_enable_enhanced_stats(ol_txrx_pdev_handle pdev);

/**
 * @brief Disable enhanced stats functionality.
 * 
 * @param pdev - the physical device object
 * @return - void
 */
void
ol_txrx_disable_enhanced_stats(ol_txrx_pdev_handle pdev);


#if ATH_BAND_STEERING
/**
 * @brief configure the inactivity timer parameters
 * @details
 *  When configuring these parameters, all associated nodes'
 *  inactivity count will also be updated.
 *
 * @pre the parameters have been sanity checked by umac band steering
 *
 * @param pdev - the data physical device object
 * @param inact_check_interval - the interval between two inactivity checks
 * @param inact_normal - the number of intervals a client has to be idle
 *                       under normal conditions to become inactive
 * @param inact_overload - the number of intervals a client has to be idle
 *                         under overload conditions to become inactive
 * @return true if parameters are set successfully; otherwise return false
 */
bool
ol_txrx_set_inact_params(ol_txrx_pdev_handle pdev,
                         u_int16_t inact_check_interval,
                         u_int16_t inact_normal,
                         u_int16_t inact_overload);

/**
 * @brief Start/stop the inactivity timer
 * @details
 *   Set inactivity timer on enable; cancel the timer on disable
 *
 * @pre the inactivity timer parameters must be set before start
 *
 * @param pdev - the data physical device object
 * @param enable - whether to start or stop the timer
 * @return true if the timer is successfully started/stopped; otherwise return false
 */
bool
ol_txrx_start_inact_timer(
    ol_txrx_pdev_handle pdev,
    bool enable);

/**
 * @brief Set the overload status of the radio
 * @details
 *   Set the overload status of the radio, updating the inactivity
 *   threshold and inactivity count for each node.
 *
 * @param pdev - the data physical device object
 * @param overload - whether the radio is overloaded or not
 */
void
ol_txrx_set_overload(
    ol_txrx_pdev_handle pdev,
    bool overload);

/**
 * @brief Mark inactivity status of the peer/node
 * @details
 *   If it becomes active, reset inactivity count to reload value;
 *   if the inactivity status changed, notify umac band steering.
 *
 * @param peer - pointer to the node's object
 * @param inactive - whether the node is inactive or not
 */
void
ol_txrx_mark_peer_inact(
    ol_txrx_peer_handle peer,
    bool inactive);

/**
 * @brief Check the inactivity status of the peer/node
 *
 * @param peer - pointer to the node's object
 * @return true if the node is inactive; otherwise return false
 */
bool
ol_txrx_peer_is_inact(
    ol_txrx_peer_handle peer);
#endif /* ATH_BAND_STEERING */

#define TX_FRAME_TYPE_DATA 0
#define TX_FRAME_TYPE_MGMT 1
#define TX_FRAME_TYPE_BEACON 2
#if ENHANCED_STATS
/**
 * @brief Get the desired stats from the message.
 * 
 * @param pdev - the physical device object
 * @param stats_base - stats buffer recieved from FW
 * @param type - stats type.
 * @return - pointer to requested stat identified by type
 */
uint32_t* ol_txrx_get_stats_base(ol_txrx_pdev_handle pdev, 
        uint32_t* stats_base, uint32_t msg_len, uint8_t type);
#endif
#endif /* _OL_TXRX_CTRL_API__H_ */
