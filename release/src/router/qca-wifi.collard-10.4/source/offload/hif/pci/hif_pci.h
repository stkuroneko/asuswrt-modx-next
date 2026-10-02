/*
 * NB: Inappropriate references to "HTC" are used in this (and other)
 * HIF implementations.  HTC is typically the calling layer, but it
 * theoretically could be some alternative.
 */

/*
 * This holds all state needed to process a pending send/recv interrupt.
 * The information is saved here as soon as the interrupt occurs (thus
 * allowing the underlying CE to re-use the ring descriptor). The
 * information here is eventually processed by a completion processing
 * thread.
 */

#include <adf_os_atomic.h> /* adf_os_atomic_read */
struct HIF_CE_completion_state {
    struct HIF_CE_completion_state *next;
    int send_or_recv;
    struct CE_handle *copyeng;
    void *ce_context;
    void *transfer_context;
    CE_addr_t data;
    unsigned int nbytes;
    unsigned int transfer_id;
    unsigned int flags;
};

/* compl_state.send_or_recv */
#define HIF_CE_COMPLETE_FREE 0
#define HIF_CE_COMPLETE_SEND 1
#define HIF_CE_COMPLETE_RECV 2

enum ol_ath_hif_pkt_ecodes {
    HIF_PIPE_NO_RESOURCE=0
};

struct HIF_CE_state ;
/* Per-pipe state. */
struct HIF_CE_pipe_info {
    /* Handle of underlying Copy Engine */
    struct CE_handle *ce_hdl;

    /* Our pipe number; facilitiates use of pipe_info ptrs. */
    A_UINT8 pipe_num;

    /* Convenience back pointer to HIF_CE_state. */
    struct HIF_CE_state *HIF_CE_state;

    /* Instantaneous number of receive buffers that should be posted */
    atomic_t recv_bufs_needed;
    adf_os_size_t buf_sz;
    adf_os_spinlock_t  recv_bufs_needed_lock;

    adf_os_spinlock_t completion_freeq_lock;
    /* Limit the number of outstanding send requests. */
    int num_sends_allowed;
    struct HIF_CE_completion_state *completion_space;
    struct HIF_CE_completion_state *completion_freeq_head;
    struct HIF_CE_completion_state *completion_freeq_tail;

    MSG_BASED_HIF_CALLBACKS pipe_callbacks;
} ;

struct HIF_CE_state {
    struct ath_hif_pci_softc *sc;
    int shut_down; /* Set to non-zero during driver shut down */
    int started;

    adf_os_spinlock_t keep_awake_lock;
    unsigned int keep_awake_count;
    A_BOOL verified_awake;

    //struct task_struct *pci_dev_inserted_thread;
    //struct completion pci_dev_inserted_thread_done;

    //wait_queue_head_t replenish_recv_buf_waitq;
    //atomic_t replenish_recv_buf_flag;
    //struct task_struct *replenish_thread;
    //struct completion post_recv_bufs_thread_done;

    adf_os_spinlock_t completion_pendingq_lock;
    /* Queue of send/recv completions that need to be processed */
    struct HIF_CE_completion_state *completion_pendingq_head;
    struct HIF_CE_completion_state *completion_pendingq_tail;
    atomic_t fw_event_pending;
    adf_os_atomic_t hif_thread_idle;

    //wait_queue_head_t service_waitq;
    //struct task_struct *compl_thread;
    //struct completion compl_thread_done;

    /* Per-pipe state. */
    struct HIF_CE_pipe_info  pipe_info[CE_COUNT_MAX];

    MSG_BASED_HIF_CALLBACKS msg_callbacks_pending; /* to be activated after BMI_DONE */
    MSG_BASED_HIF_CALLBACKS msg_callbacks_current; /* current msg callbacks in use */

    void *claimedContext;

    /* Target address used to signal a pending firmware event */
    u_int32_t fw_indicator_address;

    /* Copy Engine used for Diagnostic Accesses */
    struct CE_handle *ce_diag;

    /* For use with A_TARGET_ API */
    A_target_id_t targid;
};

extern int hif_completion_thread(struct HIF_CE_state *hif_state);

#define CE_HTT_T2H_MSG 1
#define CE_HTT_H2T_MSG 4

#define CE_DIAG_PIPE    (7)
