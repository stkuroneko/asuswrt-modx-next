/*
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
#ifndef _OL_RAWMODE_SIM_API__H_
#define _OL_RAWMODE_SIM_API__H_

#include <adf_nbuf.h>           /* adf_nbuf_t */
#include <ieee80211_var.h>      /* Generally required constructs */
#include <ol_txrx_api.h>        /* ol_txrx_vdev_t, etc*/


/* Raw Mode simulation - conversion between Raw 802.11 format and other
 * formats.
 */

/* Statistics for the Raw Mode simulation module. These do not cover events
 * occurring outside the modules (such as higher layer failures to process a
 * successfully decapped MPDU, etc.)*/

struct ol_txrx_rawmode_pkt_sim_rxstats {
    /* Rx Side simulation module statistics */

    /* Decap successes */

    /* Number of non-AMSDU bearing MPDUs decapped */
    u_int64_t num_rx_mpdu_noamsdu;

    /* Number of A-MSDU bearing MPDUs (fitting within single nbuf)
       decapped */
    u_int64_t num_rx_smallmpdu_withamsdu;

    /* Number of A-MSDU bearing MPDUs (requiring multiple nbufs) decapped */
    u_int64_t num_rx_largempdu_withamsdu;


    /* Decap errors */

    /* Number of MSDUs (contained in A-MSDU) with invalid length field */
    u_int64_t num_rx_inval_len_msdu;

    /* Number of A-MSDU bearing MPDUs which are shorter than expected from
       parsing A-MSDU fields */
    u_int64_t num_rx_tooshort_mpdu;

    /* Number of A-MSDU bearing MPDUs received which are longer than
       expected from parsing A-MSDU fields */
    u_int64_t num_rx_toolong_mpdu;

    /* Number of non-AMSDU bearing MPDUs (requiring multiple nbufs) seen
       (unhandled) */
    u_int64_t num_rx_chainedmpdu_noamsdu;

    /* Add anything else of interest */
};

struct ol_txrx_rawmode_pkt_sim_txstats {
    /* Tx Side simulation module statistics */

    /* Number of non-AMSDU bearing MPDUs encapped */
    u_int64_t num_tx_mpdu_noamsdu;

    /* Number of A-MSDU bearing MPDUs encapped */
    u_int64_t num_tx_mpdu_withamsdu;

    /* Add anything else of interest */
};

/**
 * @brief decap a list of nbufs from 802.11 Raw format to Ethernet II format
 * @details
 *  Note that the list head can be set to NULL if errors are encountered
 *  for each and every nbuf in the list.
 *
 * @param vdev - the data virtual device object
 * @param peer - the peer object
 * @param pdeliver_list_head - pointer to head of delivery list
 * @param pdeliver_list_head - pointer to tail of delivery list
 */
extern void
ol_rsim_rx_decap(struct ol_txrx_vdev_t *vdev,
        struct ol_txrx_peer_t *peer,
        adf_nbuf_t *pdeliver_list_head,
        adf_nbuf_t *pdeliver_list_tail);

/**
 * @brief encap nbuf(s) from Ethernet II format to 802.11 Raw format
 * @details
 *  Note that in the case of IP fragments, the function takes two fragments at a
 *  time and creates an A-MSDU. If it has seen the first of such fragments, it
 *  returns 0 to indicate that it needs to consume one more. In this case, the
 *  caller shouldn't pass the nbuf to lower layers.
 *  The function is simple and doesn't dynamically take decisions on A-MSDU
 *  formation. It can be extended to pack more fragments into an A-MSDU if
 *  required, but in this case there can be greater losses due to the
 *  environment. The objective of the function is only to simulate regular
 *  scatter/gather.
 *
 * @param vdev - the data virtual device object
 * @param pnbuf - pointer to nbuf
 *
 * @return - 0 on success, -1 on error, 1 if more nbufs need to be consumed. 
 */
extern int
ol_rsim_tx_encap(ol_txrx_vdev_handle vdev, adf_nbuf_t *pnbuf);

/**
 * @brief print raw mode packet simulation statistics
 *
 * @param vdev - the data virtual device object
 */
extern void
ol_txrx_print_rawmode_pkt_sim_stats(ol_txrx_vdev_handle vdev);

/**
 * @brief clear raw mode packet simulation statistics
 *
 * @param vdev - the data virtual device object
 */
extern void
ol_txrx_clear_rawmode_pkt_sim_stats(ol_txrx_vdev_handle vdev);

#endif /* _OL_RAWMODE_SIM_API__H_ */
