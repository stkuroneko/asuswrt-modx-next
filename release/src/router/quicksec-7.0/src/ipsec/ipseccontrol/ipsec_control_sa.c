/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec Control SA module.
*/
#include "sshincludes.h"
#include "sshinet.h"

#include "sshcrypt.h"
#include "ipsec_sa.h"

#include "ipsec_control.h"

#include "idtransformer.h"
#include "ip_selector.h"

#include "ipsec_control_internal.h"

#define SSH_DEBUG_MODULE "IPsecControlSa"
#define __DEBUG_MODULE__ IPsecControlSa

/** Maximum IPsec SA life time in seconds. */
#ifndef IPSEC_LIFE_TIME_MAX
#define IPSEC_LIFE_TIME_MAX (365 * 24 * 3600)
#endif

/** Minimum IPsec SA life time in seconds. */
#ifndef IPSEC_LIFE_TIME_MIN
#define IPSEC_LIFE_TIME_MIN 90
#endif

/** Minimum time in seconds for an IPsec SA to live before first rekey
    attempt. */
#ifndef IPSEC_LIFE_BEFORE_REKEY_MIN
#define IPSEC_LIFE_BEFORE_REKEY_MIN 30
#endif

/** Minimum time in seconds for an IPsec SA life to live after rekey
    starts. */
#ifndef IPSEC_LIFE_AFTER_REKEY_MIN
#define IPSEC_LIFE_AFTER_REKEY_MIN 30
#endif

/** Percentage of lifetime to use as rekey timeout.  */
#ifndef IPSEC_LIFE_REKEY_PERCENTAGE
#define IPSEC_LIFE_REKEY_PERCENTAGE 90
#endif

/** Percentage of lifetime jitter to use as rekey lifes.  */
#ifndef IPSEC_LIFE_REKEY_JITTER_PERCENTAGE
#define IPSEC_LIFE_REKEY_JITTER_PERCENTAGE 3
#endif

/** Percentage of lifetime to use as rekey retry timeout.  */
#ifndef IPSEC_LIFE_REKEY_RETRY_PERCENTAGE
#define IPSEC_LIFE_REKEY_RETRY_PERCENTAGE 2
#endif

/** Minimum lifetime to use as rekey retry timeout.  */
#ifndef IPSEC_LIFE_REKEY_RETRY_MIN
#define IPSEC_LIFE_REKEY_RETRY_MIN 5
#endif

/** Percentage of life measurement to use as rekey threshold in initiator case.
    Use a bit shorter percentage for the initiator. This way the initiator
    will most probably initiate also the rekey for the IPsec SA. */
#ifndef IPSEC_LIFE_INITIATOR_REKEY_PERCENTAGE
#define IPSEC_LIFE_INITIATOR_REKEY_PERCENTAGE 80
#endif

/** Percentage of life bytes to use as rekey threshold in responder case. */
#ifndef IPSEC_LIFE_RESPONDER_REKEY_PERCENTAGE
#define IPSEC_LIFE_RESPONDER_REKEY_PERCENTAGE 90
#endif

/** Time in seconds for IPsec SA to live after sending delete
    notification. */
#ifndef IPSEC_LIFE_DELETE_THRESHOLD
#define IPSEC_LIFE_DELETE_THRESHOLD 10
#endif

/** Longer delay, in seconds, after rekey before deleting IPsec SA. Used
    for IKEv2 responder and for IKEv1 responder and IKEv1 initiator
    until first inbound packet has been received. */
#ifndef IPSEC_LIFE_REKEY_DELETE_LONG_DELAY
#define IPSEC_LIFE_REKEY_DELETE_LONG_DELAY 30
#endif

#ifndef IPSEC_LIFE_REKEY_DELETE_LONG_DELAY_MIN
#define IPSEC_LIFE_REKEY_DELETE_LONG_DELAY_MIN 10
#endif

#ifndef IPSEC_LIFE_REKEY_DELETE_LONG_DELAY_MAX
#define IPSEC_LIFE_REKEY_DELETE_LONG_DELAY_MAX 60
#endif

/** Short delay, in seconds, after rekey before deleting IPsec SA. Used
    for IKEv2 initiator, and for IKEv1 initiator after first packet
    has been received on the SA. */
#ifndef IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY
#define IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY 5
#endif

#ifndef IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY_MIN
#define IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY_MIN 1
#endif

#ifndef IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY_MAX
#define IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY_MAX 10
#endif

/** Minimum delay in seconds before new rekey retry attempt. */
#ifndef IPSEC_REKEY_RETRY_INTERVAL_MIN
#define IPSEC_REKEY_RETRY_INTERVAL_MIN 10
#endif

/** Expire timeout in seconds if IPsec SA update fails. */
#ifndef IPSEC_UPDATE_FAIL_EXPIRE_TIMEOUT
#define IPSEC_UPDATE_FAIL_EXPIRE_TIMEOUT 1
#endif

/** Hard maximum limit for IPsec SA lifetime in seconds. */
#define IPSEC_LIFE_TIME_HARD_MAX (365 * 24 * 3600)

#if IPSEC_LIFE_TIME_MAX > IPSEC_LIFE_TIME_HARD_MAX
#error "IPSEC_LIFE_TIME_MAX too big."
#endif

#if IPSEC_LIFE_REKEY_PERCENTAGE < 1 || \
    IPSEC_LIFE_REKEY_PERCENTAGE >= 100

#error "IPSEC_LIFE_REKEY_PERCENTAGE is invalid."
#endif

#if (IPSEC_LIFE_BEFORE_REKEY_MIN +                                      \
     IPSEC_LIFE_AFTER_REKEY_MIN +                                       \
     IPSEC_LIFE_DELETE_THRESHOLD) > IPSEC_LIFE_TIME_MIN

#error "IPSEC_LIFE_TIME_MIN too small."
#endif

#define IPSEC_CONTROL_SA_SPI_MASK 0xfffffffe

/* Return minimum of two ints. */
static int
min_int(int a, int b)
{
    return a < b ? a : b;
}


/* Return maximum of two ints. */
static int
max_int(int a, int b)
{
    return a > b ? a : b;
}

static uint64_t
ipsec_control_rand(
        struct IPsecControl *ipsec_control)
{
    ipsec_control->seed =
        ipsec_control->seed * 6364136223846793005 + 1442695040888963407;

    return (ipsec_control->seed & 0xffffffffffffffffLL);
}

/* Compute and return a percentage of an int. */
static int
percent_of(
        int percent,
        int value)
{
    if (value > 10000000)
    {
        return (value / 100) * percent;
    }
    else
    {
        return (value * percent) / 100;
    }
}

/* Compute and return a percentage of an uint64_t. */
static uint64_t
uint64_percent_of(
        uint64_t percent,
        uint64_t value)
{
    if (value > 10000000)
    {
        return (value / 100) * percent;
    }
    else
    {
        return (value * percent) / 100;
    }
}

/* Compute and return a jitter of an uint64_t. */
static int
calculate_jitter(
        struct IPsecControl *ipsec_control,
        int percent,
        int value)
{
    int percent_value;
    int jitter;

    percent_value = percent_of(percent, value);
    if (percent_value < 3)
        percent_value = 3;

    jitter = ipsec_control_rand(ipsec_control) % percent_value;

    return jitter;
}

/* Compute and return a jitter of an uint64_t. */
static uint64_t
uint64_calculate_jitter(
        struct IPsecControl *ipsec_control,
        uint64_t percent,
        uint64_t value)
{
    uint64_t percent_value = uint64_percent_of(percent, value);
    uint64_t jitter;

    jitter = ipsec_control_rand(ipsec_control) % percent_value;

    return jitter;
}

/* Limit integer value to a range. */
static int
force_to_range(int value, int min, int max)
{
    return min_int(max, max_int(value, min));
}


static void
ipsec_control_data_plane_install_outbound(
        struct IPsecSa *ipsec_sa);

#define IPSEC_SA_CIRCLE_FOR_OTHERS(__other, __ipsec_sa)     \
    for ((__other) = (__ipsec_sa)->circle_next;             \
         (__other) != (__ipsec_sa);                         \
         (__other) = (__other)->circle_next)                \


static void
ipsec_control_sa_circle_init(
        struct IPsecSa *ipsec_sa)
{
    ASSERT(ipsec_sa->circle_next == NULL);

    ipsec_sa->circle_next = ipsec_sa;
}

static void
ipsec_control_sa_circle_link(
        struct IPsecSa *ipsec_sa_circle,
        struct IPsecSa *ipsec_sa)
{
    ASSERT(ipsec_sa->circle_next == NULL);

    ipsec_sa->circle_next = ipsec_sa_circle->circle_next;
    ipsec_sa_circle->circle_next = ipsec_sa;
}

static void
ipsec_control_sa_circle_unlink(
        struct IPsecSa *ipsec_sa)
{
    struct IPsecSa *next;

    next = ipsec_sa->circle_next;
    while (next->circle_next != ipsec_sa)
    {
        next = next->circle_next;
    }

    next->circle_next = ipsec_sa->circle_next;
    ipsec_sa->circle_next = NULL;
}

static bool
ipsec_control_sa_circle_is_empty(
        struct IPsecSa *ipsec_sa)
{
    return ipsec_sa->circle_next == ipsec_sa;
}

/**
   Function to return the remaining life time in seconds of the given
   IPsec SA.
 */
static int
ipsec_control_sa_life_left(
        struct IPsecSa *ipsec_sa)
{
    long seconds = 0;

    if (ipsec_sa->timeout_registered == true)
    {
        ssh_timeout_time_left(&ipsec_sa->timeout, &seconds, NULL);
    }

    seconds += ipsec_sa->life_to_live;

    return (int) seconds;
}


/**
   Function to log an IPsec SA event.
 */
static void
ipsec_control_sa_log_event(
        IPsecControlSaEvents event,
        struct IPsecSa *ipsec_sa);


/**
   Function to check if a rekey procedure can be started for an IPsec SA.
 */
static bool
ipsec_control_sa_rekey_possible(
        struct IPsecSa *ipsec_sa);


/**
   Function to initiate a rekey procedure for an IPsec SA.
 */
static void
ipsec_control_initiate_rekey(
        struct IPsecSa *ipsec_sa);


/**
   Function to mark an SA as rekeyed and trigger for quick deletion.
 */
static void
ipsec_control_sa_rekeyed(
        struct IPsecSa *ipsec_sa,
        bool quick_delete);

static void
ipsec_control_sa_rekeyed_spi(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi,
        bool quick_delete);

static void
ipsec_control_sa_set_rekey_timer(
        struct IPsecSa *ipsec_sa);

/**
   Function to initiate a procedure to send delete notification of an
   IPsec SA.
 */
static void
ipsec_control_initiate_deletion(
        struct IPsecSa *ipsec_sa);


/**
   Function to destroy an IPsec SA.
 */
static void
ipsec_control_sa_destroy(
        struct IPsecSa *ipsec_sa);


/**
   Function to handle internal install of an IPsec SA.
 */
static void
ipsec_control_sa_event_installed(
        struct IPsecSa *ipsec_sa);


/**
   Function to handle internal deletion of an IPsec SA.
 */
static void
ipsec_control_sa_uninstall(
        struct IPsecSa *ipsec_sa);

/**
   Function to initiate a idle event if idle timeout of IPsec SA has
   been expired.
 */
static void
ipsec_control_sa_idle_timeout(
        struct IPsecSa *ipsec_sa);


/**
   Function to cancel a timeout of the IPsec SA.
 */
static void
ipsec_control_sa_timeout_cancel(
        struct IPsecSa *ipsec_sa);


/**
   Function IPsec SA timeout call backs. When called delivers the
   timeout event specified in the IPsec SA to the SA.
 */
static void
ipsec_control_sa_sshtimeoutcallback(
        void *param);


/**
   Function to register a timeout for the IPsec SA and set the event
   the timeout is registered for.
 */
static void
ipsec_control_sa_timeout_register(
        struct IPsecSa *ipsec_sa,
        IPsecControlSaEvents event,
        unsigned int seconds);


/**
   Function to register an expire timeout for the IPsec SA.
 */
static void
ipsec_control_sa_expire_timeout_register(
        struct IPsecSa *ipsec_sa,
        unsigned int expire_timeout);


/**
   Function to handle an IPsec SA event.
 */
static void
ipsec_control_sa_handle_event(
        struct IPsecSa *ipsec_sa,
        IPsecControlSaEvents event);


/**
   Function allocate a free inbound_spi for a new IPsec SA. Mark it as
   rekey for rekeyed_spi if it is nonzero.
 */
static bool
ipsec_control_sa_allocate_inbound_spi(
        struct IPsecControl *ipsec_control,
        struct IPsecSa **ipsec_sa_p);

/**
   Function to allocate memory for IPsec SA and link it to the pending
   list.
 */
static bool
ipsec_control_sa_allocate(
        struct IPsecControl *ipsec_control,
        struct IPsecSa **ipsec_sa_p,
        uint32_t inbound_spi);


/**
   Function to free an IPsec SA. Handles removal from either pending
   of active list and freeing of the memory.
 */
static void
ipsec_control_sa_free(
        struct IPsecSa *ipsec_sa);


/** This is a public function; documented in ipsec_sa.h. */
bool
ipsec_sa_configure(
        struct IPsecControl *ipsec_control,
        void *callback_param,
        IPsecSaEventCb *event_callback,
        IPsecSaEventUnknownSpiCb *unknown_spi_callback)
{
    bool success = true;

    if (success == true)
    {
        if (event_callback != NULL)
        {
            ipsec_control->event_callback = event_callback;
        }
        else
        {
            IPSEC_CONTROL_DEBUG(
                    FAIL,
                    ipsec_control,
                    "No callback defined");

            success = false;
        }
    }
    if (success == true)
    {
        if (unknown_spi_callback != NULL)
        {
            ipsec_control->unknown_spi_callback = unknown_spi_callback;
        }
        else
        {
            IPSEC_CONTROL_DEBUG(
                    FAIL,
                    ipsec_control,
                    "No callback defined");

            success = false;
        }
    }

    if (success == true)
    {
        ipsec_control->ipsec_life_rekey_delete_long_delay =
            IPSEC_LIFE_REKEY_DELETE_LONG_DELAY;
        if (ipsec_control->ipsec_life_rekey_delete_long_delay <
            IPSEC_LIFE_REKEY_DELETE_LONG_DELAY_MIN)
        {
            ipsec_control->ipsec_life_rekey_delete_long_delay =
                IPSEC_LIFE_REKEY_DELETE_LONG_DELAY_MIN;
        }
        if (ipsec_control->ipsec_life_rekey_delete_long_delay >
            IPSEC_LIFE_REKEY_DELETE_LONG_DELAY_MAX)
        {
            ipsec_control->ipsec_life_rekey_delete_long_delay =
                IPSEC_LIFE_REKEY_DELETE_LONG_DELAY_MAX;
        }

        if (ipsec_control->ipsec_life_rekey_delete_short_delay == 0)
        {
            ipsec_control->ipsec_life_rekey_delete_short_delay =
                IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY;
        }
        else
        {
            if (ipsec_control->ipsec_life_rekey_delete_short_delay <
                IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY_MIN)
            {
                ipsec_control->ipsec_life_rekey_delete_short_delay =
                    IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY_MIN;
            }
            if (ipsec_control->ipsec_life_rekey_delete_short_delay >
                IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY_MAX)
            {
                ipsec_control->ipsec_life_rekey_delete_short_delay =
                    IPSEC_LIFE_REKEY_DELETE_SHORT_DELAY_MAX;
            }
        }
        ipsec_control->seed = 1;
    }

    if (success == true)
    {
        ipsec_control->param = callback_param;
    }
    else
    {
        ipsec_sa_unconfigure(ipsec_control);
    }

    if (success == true)
    {
        IPSEC_CONTROL_DEBUG(
                HIGH,
                ipsec_control,
                "Initialized.");
    }

    return success;
}


/** This is a public function; documented in ipsec_sa.h. */
void
ipsec_sa_unconfigure(
        struct IPsecControl *ipsec_control)
{
    if (ipsec_control != NULL)
    {
        IPSEC_CONTROL_DEBUG(
                HIGH,
                ipsec_control,
                "Uninitializing.");

        ipsec_control->param = NULL;
        ipsec_control->unknown_spi_callback = NULL;
        ipsec_control->event_callback = NULL;
    }
}


/** This is a public function; documented in ipsec_sa.h. */
bool
ipsec_sa_allocate(
        struct IPsecControl *ipsec_control,
        uint32_t *inbound_spi)
{
    struct IPsecSa *ipsec_sa = NULL;
    bool ok;

    ok =
        ipsec_control_sa_allocate_inbound_spi(
                ipsec_control,
                &ipsec_sa);
    if (ok == true)
    {
        uint32_t chain_id = ipsec_sa->params.inbound_spi;

        ipsec_sa->chain_id = chain_id;
        ipsec_sa->params.event_id_inbound = chain_id;
        ipsec_sa->params.event_id_outbound =
            chain_id | ~IPSEC_CONTROL_SA_SPI_MASK;

        ipsec_control_sa_circle_init(ipsec_sa);

        ipsec_control_db_sa_insert_chain_id(
                ipsec_control,
                ipsec_sa);

        *inbound_spi = ipsec_sa->params.inbound_spi;
    }

    return ok;
}


/** This is a public function; documented in ipsec_sa.h. */
bool
ipsec_sa_allocate_rekey(
        struct IPsecControl *ipsec_control,
        uint32_t rekeyed_spi,
        uint32_t *rekey_spi)
{
    struct IPsecSa *rekeyed_ipsec_sa;
    struct IPsecSa *ipsec_sa;

    bool ok = true;

    rekeyed_ipsec_sa =
        ipsec_control_db_sa_lookup(
                ipsec_control,
                rekeyed_spi);
    if (rekeyed_ipsec_sa == NULL)
    {
        IPSEC_CONTROL_DEBUG(
                LOW,
                ipsec_control,
                "Rekey SPI allocation failed: SPI 0x%.8x not found.",
                rekeyed_spi);
        ok = false;
    }

    if (ok == true)
    {
        ok =
            ipsec_control_sa_allocate_inbound_spi(
                    ipsec_control,
                    &ipsec_sa);
    }

    if (ok == true)
    {
        int expire_timeout;

        expire_timeout = ipsec_control_sa_life_left(rekeyed_ipsec_sa);

        rekeyed_ipsec_sa->rekey_attempt++;

        ipsec_control_sa_expire_timeout_register(
                rekeyed_ipsec_sa,
                expire_timeout);

        ipsec_sa->chain_id = rekeyed_ipsec_sa->chain_id;
        ipsec_sa->params.event_id_inbound =
            rekeyed_ipsec_sa->params.event_id_inbound;

        ipsec_sa->params.event_id_outbound =
            rekeyed_ipsec_sa->params.event_id_outbound;

        ipsec_sa->params.rekeyed_inbound_spi = rekeyed_spi;
        ipsec_sa->params.rekey = true;

        ipsec_control_sa_circle_link(rekeyed_ipsec_sa, ipsec_sa);

        *rekey_spi = ipsec_sa->params.inbound_spi;
    }

    return ok;
}


static bool
ipsec_control_sa_allocate_inbound_spi(
        struct IPsecControl *ipsec_control,
        struct IPsecSa **ipsec_sa_p)
{
    unsigned char array[4];
    uint32_t spi;
    uint32_t attempts, i;
    const uint32_t max_spi = 0xfffffffe;
    const uint32_t min_spi = IPSEC_CONTROL_POLICY_ID_MAX + 1;

    /* We can always skip the NAT-T problem values. */
    const bool for_esp = true;

    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "SPI Allocation started.");

    attempts = 0;
    while (attempts < 1000)
    {
        attempts++;

        for (i = 0; i < 4; i++)
        {
            array[i] = ssh_random_get_byte();
        }

        spi = SSH_GET_32BIT(array);

        spi %= (max_spi - min_spi + 1);
        spi += min_spi;
        spi &= IPSEC_CONTROL_SA_SPI_MASK;

        ASSERT(spi >= min_spi && spi <= max_spi);
        /* Never allocate the bit sequence `0010' for the SPI bits 27-24
           for inbound ESP SPI.  This is needed to distinguish between
           different NAT-T drafts.  If this is changed, you must also
           modify the inbound UDP 500 traffic handling. */
        if (for_esp && (spi & 0x0f000000) == 0x02000000)
        {
            continue;
        }

        /* Check if this SPI value is in active sa list, if so then try
           again. */
        if (ipsec_control_db_sa_lookup(
                    ipsec_control,
                    spi)
            != NULL)
        {
            continue;
        }

        /* SPI value is used as chain id for the SAs. */
        if (ipsec_control_db_sa_lookup_by_chain_id(
                    ipsec_control,
                    spi)
            != NULL)
        {
            continue;
        }

        if (ipsec_control_sa_allocate(
                    ipsec_control,
                    ipsec_sa_p,
                    spi)
            == true)
        {
            IPSEC_CONTROL_DEBUG(
                    LOW,
                    ipsec_control,
                    "SPI Allocation succeeded.");
            return true;
        }
        else
        {
            IPSEC_CONTROL_DEBUG(
                    FAIL,
                    ipsec_control,
                    "SPI Allocation failed.");
            return false;
        }
    }

    IPSEC_CONTROL_DEBUG(
            FAIL,
            ipsec_control,
            "SPI Allocation failed; Attempts overrun.");

    return false;
}

static bool
ipsec_control_sa_rekey_ongoing(
        struct IPsecSa *ipsec_sa)
{
    struct IPsecSa *ipsec_sa_rekeying;
    bool ongoing = false;

    IPSEC_SA_CIRCLE_FOR_OTHERS(ipsec_sa_rekeying, ipsec_sa)
    {
        if (ipsec_sa_rekeying->params.rekeyed_inbound_spi ==
            ipsec_sa->params.inbound_spi)
        {
            ongoing = true;
            break;
        }
    }

    return ongoing;
}


static void
ipsec_control_sa_restart_rekey(
        struct IPsecControl *ipsec_control,
        uint32_t rekeyed_inbound_spi)
{
    struct IPsecSa *ipsec_sa;

    ipsec_sa =
        ipsec_control_db_sa_lookup(
                ipsec_control,
                rekeyed_inbound_spi);
    if (ipsec_sa != NULL &&
        ipsec_sa->params.rekeyed == false &&
        ipsec_control_sa_rekey_ongoing(ipsec_sa) == false)
    {
        IPSEC_SA_DEBUG(
                HIGH,
                ipsec_sa,
                "Rekey attempt by SPI 0x%.8x failed.",
                ipsec_sa->params.inbound_spi);

        ipsec_control_sa_set_rekey_timer(
                ipsec_sa);
    }
}

/** This is a public function; documented in ipsec_sa.h. */
void
ipsec_sa_free(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi)
{
    struct IPsecSa *ipsec_sa;
    uint32_t rekeyed_inbound_spi;

    ipsec_sa =
        ipsec_control_db_sa_lookup(
                ipsec_control,
                inbound_spi);

    ASSERT(ipsec_sa != NULL);
    ASSERT(ipsec_sa->pending == true);

    IPSEC_SA_DEBUG(
            LOW,
            ipsec_sa,
            "SPI freed.");

    rekeyed_inbound_spi = ipsec_sa->params.rekeyed_inbound_spi;

    ipsec_control_sa_free(ipsec_sa);

    if (rekeyed_inbound_spi != 0)
    {
        ipsec_control_sa_restart_rekey(
                ipsec_control,
                rekeyed_inbound_spi);
    }
}

static void
ipsec_sa_responder_simultaneous_won(
        struct IPsecControl *ipsec_control,
        uint32_t spi)
{
    struct IPsecSa *ipsec_sa;

    ipsec_sa = ipsec_control_db_sa_lookup(ipsec_control, spi);
    if (ipsec_sa != NULL)
    {
        ASSERT(ipsec_sa->params.initiator == false);

        IPSEC_SA_DEBUG(
                LOW,
                ipsec_sa,
                "Responder won simultaneous rekey.");

        ipsec_sa->ikev2_simultaneous_rekey = IPSEC_CONTROL_IKEV2_REKEY_WINNER;

        if (ipsec_sa->first_packet_received == true &&
            ipsec_sa->outbound_installed == false)
        {
            ipsec_control_data_plane_install_outbound(
                    ipsec_sa);
        }

        ipsec_control_sa_rekeyed_spi(
                ipsec_control,
                ipsec_sa->params.rekeyed_inbound_spi,
                false);
    }
    else
    {
        IPSEC_CONTROL_DEBUG(
                LOW,
                ipsec_control,
                "Simultaneous winner IPsec SA inbound SPI 0x%x not found.",
                spi);
    }
}


static void
ipsec_sa_responder_simultaneous_lost(
        struct IPsecControl *ipsec_control,
        uint32_t spi)
{
    struct IPsecSa *ipsec_sa;

    ipsec_sa = ipsec_control_db_sa_lookup(ipsec_control, spi);
    if (ipsec_sa != NULL)
    {
        ASSERT(ipsec_sa->params.initiator == false);

        IPSEC_SA_DEBUG(
                LOW,
                ipsec_sa,
                "Responder lost simultaneous rekey. "
                 "Marking as rekeyed for deletion.");

        ipsec_sa->ikev2_simultaneous_rekey = IPSEC_CONTROL_IKEV2_REKEY_LOSER;

        ipsec_control_sa_rekeyed(ipsec_sa, false);
    }
    else
    {
        IPSEC_CONTROL_DEBUG(
                LOW,
                ipsec_control,
                "Responder simultaneous loser IPsec SA inbound "
                "SPI 0x%.8x not found.",
                spi);
    }
}

static void
ipsec_control_sa_rekeyed_spi(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi,
        bool quick_delete)
{
    struct IPsecSa *ipsec_sa;

    ipsec_sa =
        ipsec_control_db_sa_lookup(
                ipsec_control,
                inbound_spi);
    if (ipsec_sa != NULL)
    {
        IPSEC_SA_DEBUG(
                HIGH,
                ipsec_sa,
                "Rekeyed SPI 0x%.8x.",
                inbound_spi);

        ipsec_control_sa_rekeyed(
                ipsec_sa,
                quick_delete);
    }
}


/** This is a public function; documented in ipsec_sa.h. */
void
ipsec_sa_responder_set_simultaneous_rekey(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi,
        uint32_t simultaneous_inbound_spi)
{
    struct IPsecSa *ipsec_sa;
    struct IPsecSa *simultaneous_sa;

    ipsec_sa =
        ipsec_control_db_sa_lookup(
                ipsec_control,
                inbound_spi);

    simultaneous_sa =
        ipsec_control_db_sa_lookup(
                ipsec_control,
                simultaneous_inbound_spi);

    if (ipsec_sa != NULL && simultaneous_sa != NULL)
    {
        ipsec_sa->ikev2_simultaneous_rekey =
            IPSEC_CONTROL_IKEV2_REKEY_ONGOING;

        ipsec_sa->ikev2_simultaneous_inbound_spi =
            simultaneous_inbound_spi;

        simultaneous_sa->ikev2_simultaneous_rekey =
            IPSEC_CONTROL_IKEV2_REKEY_ONGOING;

        simultaneous_sa->ikev2_simultaneous_inbound_spi =
            inbound_spi;

        IPSEC_SA_DEBUG(
                LOW,
                ipsec_sa,
                "Simultaneous rekey ongoing: "
                "Responder SPI 0x%.8x, Initiator SPI %x.8x",
                inbound_spi,
                simultaneous_inbound_spi);
    }
}

/** This is a public function; documented in ipsec_sa.h. */
void
ipsec_sa_initiator_set_simultaneous_won(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi)
{
    struct IPsecSa *ipsec_sa;

    ipsec_sa =
        ipsec_control_db_sa_lookup(
                ipsec_control,
                inbound_spi);

    if (ipsec_sa != NULL)
    {
        ipsec_sa->ikev2_simultaneous_rekey = IPSEC_CONTROL_IKEV2_REKEY_WINNER;

        IPSEC_SA_DEBUG(
                LOW,
                ipsec_sa,
                "Simultaneous winner, loser IPsec SA inbound SPI 0x%.8x",
                ipsec_sa->ikev2_simultaneous_inbound_spi);
    }
    else
    {
        IPSEC_CONTROL_DEBUG(
                LOW,
                ipsec_control,
                "Simultaneous winner IPsec SA inbound SPI 0x%x not found.",
                 inbound_spi);
    }
}

/** This is a public function; documented in ipsec_sa.h. */
void
ipsec_sa_initiator_set_simultaneous_lost(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi)
{
    struct IPsecSa *ipsec_sa;

    ipsec_sa =
        ipsec_control_db_sa_lookup(
                ipsec_control,
                inbound_spi);

    if (ipsec_sa != NULL)
    {
        ipsec_sa->ikev2_simultaneous_rekey = IPSEC_CONTROL_IKEV2_REKEY_LOSER;

        IPSEC_SA_DEBUG(
                LOW,
                ipsec_sa,
                "Simultaneous loser, winner IPsec SA inbound SPI 0x%.8x",
                ipsec_sa->ikev2_simultaneous_inbound_spi);
    }
    else
    {
        IPSEC_CONTROL_DEBUG(
                LOW,
                ipsec_control,
                "Simultaneous loser IPsec SA inbound SPI 0x%.8x not found.",
                 inbound_spi);
    }
}

static bool
ipsec_control_data_plane_install(
        struct IPsecSa *ipsec_sa,
        struct IPsecSaKeyMaterial *ipsec_sa_keymaterial)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;
    bool status = true;

    if (ipsec_control->control_callbacks != NULL &&
        ipsec_control->control_callbacks->install_sa_cb != NULL)
    {
        status =
            ipsec_control->control_callbacks->install_sa_cb(
                    ipsec_control->control_param,
                    &ipsec_sa->params,
                    &ipsec_sa->endpoints,
                    &ipsec_sa->control_sa,
                    ipsec_sa_keymaterial);
    }

    return status;
}

static bool
ipsec_control_data_plane_install_inbound(
        struct IPsecSa *ipsec_sa,
        struct IPsecSaKeyMaterial *ipsec_sa_keymaterial)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;
    bool status = true;

    if (ipsec_control->control_callbacks != NULL &&
        ipsec_control->control_callbacks->install_inbound_sa_cb != NULL)
    {
        status =
            ipsec_control->control_callbacks->install_inbound_sa_cb(
                    ipsec_control->control_param,
                    &ipsec_sa->params,
                    &ipsec_sa->endpoints,
                    &ipsec_sa->control_sa,
                    ipsec_sa_keymaterial);
    }

    return status;
}

static void
ipsec_control_data_plane_install_outbound(
        struct IPsecSa *ipsec_sa)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;
    bool status = true;

    ASSERT(ipsec_sa->ipsec_sa_keymaterial != NULL);

    if (ipsec_control->control_callbacks != NULL &&
        ipsec_control->control_callbacks->install_outbound_sa_cb != NULL)
    {
        status =
            ipsec_control->control_callbacks->install_outbound_sa_cb(
                    ipsec_control->control_param,
                    &ipsec_sa->params,
                    &ipsec_sa->endpoints,
                    ipsec_sa->control_sa,
                    ipsec_sa->ipsec_sa_keymaterial);
    }

    if (status != true)
    {
        IPSEC_SA_DEBUG(
                FAIL,
                ipsec_sa,
                "Install outbound failed.");
    }

    ipsec_sa->outbound_installed = true;

    ssh_free(ipsec_sa->ipsec_sa_keymaterial);
    ipsec_sa->ipsec_sa_keymaterial = NULL;
}

static bool
ipsec_control_sa_inbound_only(
        struct IPsecSa *ipsec_sa)
{
    const struct IPsecSaParams *params = &ipsec_sa->params;
    bool inbound_only = false;

    if (params->rekey == true)
    {
        if (params->ikev1_sa == true && params->initiator == true)
        {
            inbound_only = true;
        }

        if (params->ikev1_sa == false && params->initiator == false)
        {
            inbound_only = true;
        }

        if (ipsec_sa->ikev2_simultaneous_rekey ==
            IPSEC_CONTROL_IKEV2_REKEY_LOSER)
        {
            inbound_only = true;
        }

        if (inbound_only == true)
        {
            if (ipsec_control_db_sa_lookup(
                        ipsec_sa->ipsec_control,
                        ipsec_sa->params.rekeyed_inbound_spi)
                == NULL)
            {
                inbound_only = false;
            }
        }
    }

    return inbound_only;
}

static void
ipsec_control_sa_configure_life_bytes_rekey(
        struct IPsecSa *ipsec_sa)
{
    if (ipsec_sa->params.life_bytes > 0)
    {
        uint64_t rekey_percentage;
        uint64_t life_bytes_jitter;
        uint64_t life_bytes_rekey;
        struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;

        if (ipsec_sa->params.initiator == true)
        {
            rekey_percentage = IPSEC_LIFE_INITIATOR_REKEY_PERCENTAGE;
        }
        else
        {
            rekey_percentage = IPSEC_LIFE_RESPONDER_REKEY_PERCENTAGE;
        }

        life_bytes_rekey =
            uint64_percent_of(
                    rekey_percentage,
                    ipsec_sa->params.life_bytes);

        life_bytes_jitter =
            uint64_calculate_jitter(
                    ipsec_control,
                    IPSEC_LIFE_REKEY_JITTER_PERCENTAGE,
                    life_bytes_rekey);

        ipsec_sa->params.life_bytes_rekey =
            life_bytes_rekey - life_bytes_jitter;
    }
}

static void
ipsec_control_sa_configure_params(
        struct IPsecSaParams *ipsec_sa_params,
        const struct IPsecSaParams *params)
{
    ipsec_sa_params->tunnel_id = params->tunnel_id;
    ipsec_sa_params->rule_id = params->rule_id;
    ipsec_sa_params->outbound_spi = params->outbound_spi;
    ipsec_sa_params->peer_handle = params->peer_handle;
    ipsec_sa_params->log_facility = params->log_facility;
    ipsec_sa_params->ipproto = params->ipproto;
    ipsec_sa_params->integrity_algorithm_id = params->integrity_algorithm_id;
    ipsec_sa_params->encryption_algorithm_id = params->encryption_algorithm_id;
    ipsec_sa_params->dh_algorithm_id = params->dh_algorithm_id;
    ipsec_sa_params->ikev1_sa = params->ikev1_sa;
    ipsec_sa_params->tunnel_mode = params->tunnel_mode;

    ipsec_sa_params->natt_local_original_address =
        params->natt_local_original_address;

    ipsec_sa_params->natt_remote_original_address =
        params->natt_remote_original_address;

    ipsec_sa_params->esn = params->esn;
    ipsec_sa_params->initiator = params->initiator;

    ipsec_sa_params->dont_fragment_bit_policy =
        params->dont_fragment_bit_policy;

    ipsec_sa_params->stateful_fragment_check = params->stateful_fragment_check;
    ipsec_sa_params->life_seconds = params->life_seconds;
    ipsec_sa_params->life_bytes = params->life_bytes;
    ipsec_sa_params->natt_keepalive_timeout = params->natt_keepalive_timeout;

    ipsec_sa_params->policy_priority = params->policy_priority;

    ipsec_sa_params->idle_timeout_threshold_seconds =
        params->idle_timeout_threshold_seconds;

    ipsec_sa_params->idle_event_interval_seconds =
        params->idle_event_interval_seconds;
}


static void
ipsec_sa_log_key(
        const char *which,
        int protocol,
        const struct InAddr *source_address,
        const struct InAddr *destination_address,
        uint32_t spi,
        TransformId algorithm,
        const unsigned char *key,
        int key_bytecount)
{
#ifdef IPSEC_CONTROL_DEBUG_KEYS
    DEBUG_HIGH(
            keys,
            "%s %s %s -> %s SPI 0x%x %s 0x%s",
            ssh_ipproto_str(protocol),
            which,
            debug_strbuf_in_addr(
                        DEBUG_STRBUF_GET(),
                        source_address),
            debug_strbuf_in_addr(
                        DEBUG_STRBUF_GET(),
                        destination_address),
            spi,
            idtransformer_to_string(algorithm),
            debug_str_hexbuf(
                    DEBUG_STRBUF_GET(),
                    key,
                    key_bytecount));
#endif
}

static void
ipsec_sa_log_keys(
        const struct IPsecSaParams *ipsec_sa_params,
        const struct IPsecSaEndpoints *ipsec_sa_endpoints,
        const struct IPsecSaKeyMaterial *ipsec_sa_keymaterial)
{
    const struct InAddr *local_address = &ipsec_sa_endpoints->local_address;
    const struct InAddr *remote_address = &ipsec_sa_endpoints->remote_address;
    bool with_encryption = false;
    bool with_integrity = false;

    if (ipsec_sa_params->ipproto == SSH_IPPROTO_ESP)
    {
        with_encryption = true;
    }

    if (ipsec_sa_params->integrity_algorithm_id != TRANSFORMID_INTEG_NONE)
    {
        with_integrity = true;
    }

    if (with_encryption == true)
    {
        ipsec_sa_log_key(
                "in  encryption",
                ipsec_sa_params->ipproto,
                remote_address,
                local_address,
                ipsec_sa_params->inbound_spi,
                ipsec_sa_params->encryption_algorithm_id,
                ipsec_sa_keymaterial->inbound_encryption_keymaterial,
                ipsec_sa_keymaterial->encryption_keymaterial_len);
    }

    if (with_integrity == true)
    {
        ipsec_sa_log_key(
                "in  integrity ",
                ipsec_sa_params->ipproto,
                remote_address,
                local_address,
                ipsec_sa_params->inbound_spi,
                ipsec_sa_params->integrity_algorithm_id,
                ipsec_sa_keymaterial->inbound_integrity_keymaterial,
                ipsec_sa_keymaterial->integrity_keymaterial_len);
    }

    if (with_encryption == true)
    {
        ipsec_sa_log_key(
                "out encryption",
                ipsec_sa_params->ipproto,
                local_address,
                remote_address,
                ipsec_sa_params->outbound_spi,
                ipsec_sa_params->encryption_algorithm_id,
                ipsec_sa_keymaterial->outbound_encryption_keymaterial,
                ipsec_sa_keymaterial->encryption_keymaterial_len);
    }

    if (with_integrity == true)
    {
        ipsec_sa_log_key(
                "out integrity ",
                ipsec_sa_params->ipproto,
                local_address,
                remote_address,
                ipsec_sa_params->outbound_spi,
                ipsec_sa_params->integrity_algorithm_id,
                ipsec_sa_keymaterial->outbound_integrity_keymaterial,
                ipsec_sa_keymaterial->integrity_keymaterial_len);
    }
}


/** This is a public function; documented in ipsec_sa.h. */
bool
ipsec_sa_install(
        struct IPsecControl *ipsec_control,
        struct IPsecSaParams *ipsec_sa_params,
        struct IPsecSaEndpoints *ipsec_sa_endpoints,
        struct IPsecSaKeyMaterial *ipsec_sa_keymaterial,
        const struct IPSelectorGroup *selector_group)
{
    struct IPsecSa *ipsec_sa = NULL;
    struct IPsecSa *ipsec_sa_outbound;
    bool status = true;
    bool is_inbound_only;

    ASSERT(ipsec_sa_params->rekeyed == false);

    ipsec_sa_outbound =
        ipsec_control_db_sa_lookup_by_outbound_spi(
                ipsec_control,
                ipsec_sa_params->outbound_spi,
                ipsec_sa_params->ipproto,
                &ipsec_sa_endpoints->remote_address,
                ipsec_sa_endpoints->remote_port);

    if (ipsec_sa_outbound != NULL)
    {
        IPSEC_CONTROL_DEBUG(
                MEDIUM,
                ipsec_control,
                "Install failed: existing outbound SA found: "
                "outbound SPI 0x%x, ipproto %d, "
                "remote address %s remote port %d.",
                (unsigned int) ipsec_sa_params->outbound_spi,
                (int) ipsec_sa_params->ipproto,
                debug_strbuf_in_addr(
                        DEBUG_STRBUF_GET(),
                        &ipsec_sa_endpoints->remote_address),
                ipsec_sa_endpoints->remote_port);

        status = false;
    }

    if (status == true)
    {
        ipsec_sa =
            ipsec_control_db_sa_lookup(
                    ipsec_control,
                    ipsec_sa_params->inbound_spi);

        ASSERT(ipsec_sa != NULL);
        ASSERT(ipsec_sa->pending == true);
        ASSERT(ipsec_sa->params.rekey == ipsec_sa_params->rekey);

        ipsec_control_sa_configure_params(&ipsec_sa->params, ipsec_sa_params);

        is_inbound_only = ipsec_control_sa_inbound_only(ipsec_sa);

        ipsec_sa->params.selector_group =
            ssh_malloc(
                    selector_group->bytecount);

        if (ipsec_sa->params.selector_group == NULL)
        {
            IPSEC_SA_DEBUG(
                    FAIL,
                    ipsec_sa,
                    "Install failed: selector allocation failed.");
            status = false;
        }

        if (is_inbound_only == true)
        {
            ipsec_sa->ipsec_sa_keymaterial =
                ssh_malloc(
                        sizeof *ipsec_sa_keymaterial);
            if (ipsec_sa->ipsec_sa_keymaterial == NULL)
            {
                IPSEC_SA_DEBUG(
                        FAIL,
                        ipsec_sa,
                        "Install failed: keymaterial allocation failed.");
                status = false;
            }
        }
    }

    if (status == true)
    {
        ipsec_sa->endpoints = *ipsec_sa_endpoints;

        memcpy(
                ipsec_sa->params.selector_group,
                selector_group,
                selector_group->bytecount);

        if (is_inbound_only == true)
        {
            memcpy(
                    ipsec_sa->ipsec_sa_keymaterial,
                    ipsec_sa_keymaterial,
                    sizeof *ipsec_sa_keymaterial);
        }

        if (ipsec_sa->params.life_seconds == 0)
        {
            ipsec_sa->params.life_seconds = IPSEC_LIFE_TIME_MAX;
        }

        ipsec_sa->params.life_seconds =
            force_to_range(
                    ipsec_sa->params.life_seconds,
                    IPSEC_LIFE_TIME_MIN,
                    IPSEC_LIFE_TIME_MAX);

        ipsec_sa->life_to_live =
            ipsec_sa->params.life_seconds - IPSEC_LIFE_DELETE_THRESHOLD;

        ipsec_control_sa_configure_life_bytes_rekey(ipsec_sa);

        ipsec_sa->pending = false;

        /* Add to data base*/
        ipsec_control_db_sa_insert_active(
                ipsec_control,
                ipsec_sa);

    }

    if (status == true)
    {
        if (is_inbound_only == true)
        {
            status =
                ipsec_control_data_plane_install_inbound(
                        ipsec_sa,
                        ipsec_sa_keymaterial);
        }
        else
        {
            ipsec_sa->outbound_installed = true;

            status =
                ipsec_control_data_plane_install(
                        ipsec_sa,
                        ipsec_sa_keymaterial);
        }
    }

    if (status == true)
    {
        ipsec_control_sa_handle_event(
                ipsec_sa,
                IPSEC_CONTROL_SA_INSTALLED);

        ipsec_sa_log_keys(
                ipsec_sa_params,
                ipsec_sa_endpoints,
                ipsec_sa_keymaterial);
    }

    return status;
}

/** This is a public function; documented in ipsec_sa.h. */
bool
ipsec_sa_import(
        struct IPsecControl *ipsec_control,
        struct IPsecSaParams *ipsec_sa_params,
        struct IPsecSaEndpoints *ipsec_sa_endpoints,
        struct IPsecSaKeyMaterial *ipsec_sa_keymaterial,
        const struct IPSelectorGroup *selector_group)
{
    struct IPsecSa *ipsec_sa = NULL;
    bool ok = true;

    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "SPI import started.");

    if (selector_group == NULL)
    {
        ok = false;
    }

    /* Check if this SPI value is in active sa list. */
    if (ipsec_control_db_sa_lookup(
                ipsec_control,
                ipsec_sa_params->inbound_spi)
        != NULL)
    {
        ok = false;
    }

    /* SPI value is used as chain id for the SAs. */
    if (ipsec_control_db_sa_lookup_by_chain_id(
                ipsec_control,
                ipsec_sa_params->inbound_spi)
        != NULL)
    {
        ok = false;
    }

    if (ok == true)
    {
        if (ipsec_control_sa_allocate(
                    ipsec_control,
                    &ipsec_sa,
                    ipsec_sa_params->inbound_spi)
            == true)
        {
            IPSEC_CONTROL_DEBUG(
                    LOW,
                    ipsec_control,
                    "SPI Allocation succeeded.");
        }
        else
        {
            IPSEC_CONTROL_DEBUG(
                    FAIL,
                    ipsec_control,
                    "SPI Allocation failed.");
            ok = false;
        }
    }

    if (ok == true)
    {
        uint32_t chain_id = ipsec_sa->params.inbound_spi;

        ipsec_sa->chain_id = chain_id;
        ipsec_sa->params.event_id_inbound = chain_id;
        ipsec_sa->params.event_id_outbound =
            chain_id | ~IPSEC_CONTROL_SA_SPI_MASK;
        ipsec_sa->params.rekey = ipsec_sa_params->rekey;
        ipsec_sa->params.seq_high = ipsec_sa_params->seq_high;
        ipsec_sa->params.seq_low = ipsec_sa_params->seq_low;

        ipsec_control_sa_circle_init(ipsec_sa);

        ipsec_control_db_sa_insert_chain_id(
                ipsec_control,
                ipsec_sa);

    }

    if (ok == true)
    {
        ok = ipsec_sa_install(
                ipsec_control,
                ipsec_sa_params,
                ipsec_sa_endpoints,
                ipsec_sa_keymaterial,
                selector_group);
    }
    if (ok == false)
    {
        IPSEC_CONTROL_DEBUG(
                FAIL,
                ipsec_control,
                "IPsec SA installation failed.");
        ipsec_control_sa_free(ipsec_sa);
    }

    return ok;
}


/** This is a public function; documented in ipsec_sa.h. */
uint32_t
ipsec_sa_find_by_outbound_spi(
        struct IPsecControl *ipsec_control,
        bool match_address,
        uint32_t spi, uint8_t ipproto,
        const struct InAddr *remote_ip,
        uint16_t remote_ike_port)
{
    struct IPsecSa *ipsec_sa = NULL;


    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "Looking for match: outbound SPI 0x%x, ipproto %d, "
            "remote address %s remote port %d.",
            (unsigned int) spi,
            (int) ipproto,
            debug_strbuf_in_addr(DEBUG_STRBUF_GET(), remote_ip),
            remote_ike_port);

    ipsec_sa =
        ipsec_control_db_sa_lookup_by_outbound_spi(
                ipsec_control,
                spi,
                ipproto,
                remote_ip,
                remote_ike_port);

    if (ipsec_sa != NULL)
    {
        IPSEC_SA_DEBUG(
                LOW,
                ipsec_sa,
                "Match!");
        return ipsec_sa->params.inbound_spi;
    }

    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "No match!");

    return 0;
}


/** This is a public function; documented in ipsec_sa.h. */
const struct IPsecSaParams *
ipsec_sa_get_params(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi)
{
    struct IPsecSa *ipsec_sa;

    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "Retrieving SA params for an inbound SPI.");

    ipsec_sa = ipsec_control_db_sa_lookup(ipsec_control, inbound_spi);

    if (ipsec_sa != NULL)
    {
        return &ipsec_sa->params;
    }

    return NULL;
}


/** This is a public function; documented in ipsec_sa.h. */
const struct IPsecSaEndpoints *
ipsec_sa_get_endpoints(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi)
{
    struct IPsecSa *ipsec_sa;

    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "Retrieving SA params for an inbound SPI.");

    ipsec_sa = ipsec_control_db_sa_lookup(ipsec_control, inbound_spi);

    if (ipsec_sa != NULL)
    {
        return &ipsec_sa->endpoints;
    }

    return NULL;
}


/** This is a public function; documented in ipsec_sa.h. */
bool
ipsec_sa_get_traffic_selectors(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi,
        const struct IPSelectorGroup **selector_group_p)
{
    struct IPsecSa *ipsec_sa;

    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "Retrieving traffic selectors for an inbound SPI.");

    ipsec_sa = ipsec_control_db_sa_lookup(ipsec_control, inbound_spi);

    if (ipsec_sa != NULL)
    {
        *selector_group_p = ipsec_sa->params.selector_group;

        ASSERT(*selector_group_p != NULL);

        return true;
    }

    return false;
}


/** This is a public function; documented in ipsec_sa.h. */
bool
ipsec_sa_is_rekeyed(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi)
{
    struct IPsecSa *ipsec_sa;

    ipsec_sa = ipsec_control_db_sa_lookup(ipsec_control, inbound_spi);

    if (ipsec_sa != NULL)
    {
        if ((ipsec_sa->params.rekeyed == true) ||
            (ipsec_sa->ikev2_simultaneous_rekey ==
             IPSEC_CONTROL_IKEV2_REKEY_LOSER))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    return false;
}

/** This is a public function; documented in ipsec_sa.h. */
bool
ipsec_sa_is_rekey_possible(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi,
        int *time_left_seconds)
{
    struct IPsecSa *ipsec_sa;
    bool rekey_possible = false;

    *time_left_seconds = 0;

    ipsec_sa = ipsec_control_db_sa_lookup(ipsec_control, inbound_spi);

    if (ipsec_sa != NULL)
    {
        if (ipsec_sa->timeout_registered == true)
        {
            rekey_possible = ipsec_control_sa_rekey_possible(ipsec_sa);

            if (rekey_possible == true)
            {
                long seconds = 0;

                ssh_timeout_time_left(
                        &ipsec_sa->timeout,
                        &seconds,
                        NULL);

                *time_left_seconds = (int) seconds;
            }

        }
    }

    return rekey_possible;
}


/** This is a public function; documented in ipsec_sa.h. */
int
ipsec_sa_delete_all_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle)
{
    struct IPsecSa *ipsec_sa;
    int delete_count = 0;

    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "IPsec SA mass deletion with peer_handle 0x%lx: Started.",
             (unsigned long) peer_handle);

    ipsec_sa =
        ipsec_control_db_sa_lookup_first_by_peer_handle(
                ipsec_control,
                peer_handle);

    while (ipsec_sa != NULL)
    {
        uint32_t inbound_spi =  ipsec_sa->params.inbound_spi;
        delete_count++;

        ipsec_control_sa_handle_event(ipsec_sa, IPSEC_CONTROL_SA_DELETE);

        ipsec_sa =
            ipsec_control_db_sa_lookup_next_by_peer_handle(
                    ipsec_control,
                    peer_handle,
                    inbound_spi);
    }

    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "IPsec SA mass deletion with peer_handle 0x%lx: Stopped.",
             (unsigned long) peer_handle);

    return delete_count;
}

/** This is a public function; documented in ipsec_sa.h. */
int
ipsec_sa_destroy_all_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle)
{
    struct IPsecSa *ipsec_sa;
    int delete_count = 0;

    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "IPsec SA mass destroy with peer_handle 0x%lx: Started.",
             (unsigned long) peer_handle);

    ipsec_sa =
        ipsec_control_db_sa_lookup_first_by_peer_handle(
                ipsec_control,
                peer_handle);

    while (ipsec_sa != NULL)
    {
        uint32_t inbound_spi =  ipsec_sa->params.inbound_spi;
        delete_count++;

        ipsec_control_sa_destroy(ipsec_sa);

        ipsec_sa =
            ipsec_control_db_sa_lookup_next_by_peer_handle(
                    ipsec_control,
                    peer_handle,
                    inbound_spi);
    }

    IPSEC_CONTROL_DEBUG(
            LOW,
            ipsec_control,
            "IPsec SA mass destroy with peer_handle 0x%lx: Stopped.",
             (unsigned long) peer_handle);

    return delete_count;
}

/** This is a public function; documented in ipsec_sa.h. */
void
ipsec_sa_delete(
        struct IPsecControl *ipsec_control,
        uint32_t inbound_spi)
{
    struct IPsecSa *ipsec_sa;

    ipsec_sa = ipsec_control_db_sa_lookup(ipsec_control, inbound_spi);
    if (ipsec_sa != NULL)
    {
        IPSEC_SA_DEBUG(
                LOW,
                ipsec_sa,
                "IPsec SA deleted with inbound spi.");

        ipsec_control_sa_destroy(ipsec_sa);
    }
    else
    {
        IPSEC_CONTROL_DEBUG(
                LOW,
                ipsec_control,
                "IPsec SA not found (for deletion) with inbound spi 0x%lx.",
                 (unsigned long) inbound_spi);
    }
}


static void
ipsec_control_data_plane_update(
        struct IPsecSa *ipsec_sa,
        struct IPsecSaEndpoints *ipsec_sa_endpoints)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;

    if (ipsec_control->control_callbacks != NULL &&
        ipsec_control->control_callbacks->update_sa_cb != NULL)
    {
        bool sas_updated = false;
        sas_updated = ipsec_control->control_callbacks->update_sa_cb(
                ipsec_control->control_param,
                &ipsec_sa->params,
                &ipsec_sa->endpoints,
                ipsec_sa_endpoints,
                ipsec_sa->control_sa);
        /* start a rekey if dataplane does not support updating SA's */
        if (sas_updated == false)
        {
            ipsec_control_sa_timeout_register(
                    ipsec_sa,
                    IPSEC_CONTROL_SA_REKEY,
                    0);
        }
    }
}


/** This is a public function; documented in ipsec_sa.h. */
bool
ipsec_sa_update_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle,
        int path_id,
        struct IPsecSaEndpoints *ipsec_sa_endpoints)
{
    struct IPsecSa *ipsec_sa;

    IPSEC_CONTROL_DEBUG(
            MEDIUM,
            ipsec_control,
            "IPsec SAs with peer handle 0x%lx "
            "updated to use local address %s and peer %s:%d natt %s.",
            (unsigned long) peer_handle,
            debug_strbuf_in_addr(
                    DEBUG_STRBUF_GET(),
                    &ipsec_sa_endpoints->local_address),
            debug_strbuf_in_addr(
                    DEBUG_STRBUF_GET(),
                    &ipsec_sa_endpoints->remote_address),
            ipsec_sa_endpoints->remote_port,
            ipsec_sa_endpoints->natt ? "enabled" : "disabled");

    ipsec_sa =
        ipsec_control_db_sa_lookup_first_by_peer_handle(
                ipsec_control,
                peer_handle);
    while (ipsec_sa != NULL)
    {
        uint32_t inbound_spi = ipsec_sa->params.inbound_spi;
        struct IPsecSa *ipsec_sa_outbound;

        ipsec_sa_outbound =
            ipsec_control_db_sa_lookup_by_outbound_spi(
                    ipsec_control,
                    ipsec_sa->params.outbound_spi,
                    ipsec_sa->params.ipproto,
                    &ipsec_sa_endpoints->remote_address,
                    ipsec_sa_endpoints->remote_port);

        if (ipsec_sa_outbound != NULL && ipsec_sa_outbound != ipsec_sa)
        {
            IPSEC_CONTROL_DEBUG(
                    MEDIUM,
                    ipsec_control,
                    "Update failed: existing outbound SA found: "
                    "outbound SPI 0x%x, ipproto %d, "
                    "remote address %s remote port %d, "
                    "setting expire with timeout %d.",
                    (unsigned int) ipsec_sa->params.outbound_spi,
                    (int) ipsec_sa->params.ipproto,
                    debug_strbuf_in_addr(
                            DEBUG_STRBUF_GET(),
                            &ipsec_sa_endpoints->remote_address),
                    ipsec_sa_endpoints->remote_port,
                    IPSEC_UPDATE_FAIL_EXPIRE_TIMEOUT);

            ipsec_control_sa_expire_timeout_register(
                    ipsec_sa,
                    IPSEC_UPDATE_FAIL_EXPIRE_TIMEOUT);
        }
        else
        {
            ipsec_control_data_plane_update(
                    ipsec_sa,
                    ipsec_sa_endpoints);

            /* Update endpoints after data plane is updated. */
            ipsec_sa->endpoints = *ipsec_sa_endpoints;
        }

        ipsec_sa =
            ipsec_control_db_sa_lookup_next_by_peer_handle(
                    ipsec_control,
                    peer_handle,
                    inbound_spi);
    }

    return true;
}


/** This is a public function; documented in ipsec_sa.h. */
uint32_t
ipsec_sa_find_matching_sa(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle,
        const struct IPSelectorGroup *selector_group)
{
    struct IPsecSa *ipsec_sa;

    ipsec_sa =
        ipsec_control_db_sa_lookup_first_by_peer_handle(
                ipsec_control,
                peer_handle);
    while (ipsec_sa != NULL)
    {
        uint32_t inbound_spi = ipsec_sa->params.inbound_spi;

        if (selector_group->bytecount ==
            ipsec_sa->params.selector_group->bytecount &&
            memcmp(
                    selector_group,
                    ipsec_sa->params.selector_group,
                    selector_group->bytecount) == 0)
        {
            return inbound_spi;
        }

        ipsec_sa =
            ipsec_control_db_sa_lookup_next_by_peer_handle(
                    ipsec_control,
                    peer_handle,
                    inbound_spi);
    }

    return 0;
}


static void
ipsec_control_sa_rekeyed(
        struct IPsecSa *ipsec_sa,
        bool quick_delete)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;
    int deletion_timeout;
    int life_left;

    deletion_timeout = ipsec_control->ipsec_life_rekey_delete_long_delay;
    if (quick_delete == true)
    {
        deletion_timeout = ipsec_control->ipsec_life_rekey_delete_short_delay;
    }

    life_left = ipsec_control_sa_life_left(ipsec_sa);

    deletion_timeout = min_int(life_left, deletion_timeout);

    if (ipsec_sa->params.rekeyed)
    {
        if (deletion_timeout < life_left)
        {
            IPSEC_SA_DEBUG(
                    MEDIUM,
                    ipsec_sa,
                    "Already rekeyed. Shortening life from %d to %d",
                     life_left,
                     deletion_timeout);
        }
        else
        {
            IPSEC_SA_DEBUG(
                    MEDIUM,
                    ipsec_sa,
                    "Already rekeyed.");
            return;
        }
    }

    ipsec_sa->params.rekeyed = true;

    if (ipsec_sa->delete_received || ipsec_sa->delete_sent)
    {
        IPSEC_SA_DEBUG(
                MEDIUM,
                ipsec_sa,
                "Rekeyed SA already deleted.");
    }
    else
    {
        IPSEC_SA_DEBUG(
                MEDIUM,
                ipsec_sa,
                "Rekeyed. Deletion timeout %d.",
                deletion_timeout);

        ipsec_sa->life_to_live = 0;
        ipsec_control_sa_timeout_register(
                ipsec_sa,
                IPSEC_CONTROL_SA_REKEY_DELETE,
                deletion_timeout);
    }
}


static void
ipsec_control_sa_timeout_cancel(
        struct IPsecSa *ipsec_sa)
{
    if (ipsec_sa->timeout_registered == true)
    {
        ASSERT(ipsec_sa->pending == false);

        ssh_cancel_timeout(&ipsec_sa->timeout);
        ipsec_sa->timeout_event = IPSEC_CONTROL_SA_NONE;
        ipsec_sa->timeout_registered = false;
    }
}


static void
ipsec_control_sa_timeout_register(
        struct IPsecSa *ipsec_sa,
        IPsecControlSaEvents event,
        unsigned int seconds)
{
    ASSERT(ipsec_sa->pending == false);

    ipsec_control_sa_timeout_cancel(ipsec_sa);

    ipsec_sa->timeout_event = event;
    ipsec_sa->timeout_registered = true;
    ssh_register_timeout(
            &ipsec_sa->timeout,
            seconds,
            0,
            ipsec_control_sa_sshtimeoutcallback,
            ipsec_sa);
}


static void
ipsec_control_sa_expire_timeout_register(
        struct IPsecSa *ipsec_sa,
        unsigned int expire_timeout)
{
    ipsec_sa->life_to_live = 0;
    ipsec_control_sa_timeout_register(
            ipsec_sa,
            IPSEC_CONTROL_SA_EXPIRE,
            expire_timeout);
}


static void
ipsec_control_sa_handle_event(
        struct IPsecSa *ipsec_sa,
        IPsecControlSaEvents event)
{
    bool deleted = false;

    ipsec_control_sa_log_event(event, ipsec_sa);

    switch (event)
    {
    case IPSEC_CONTROL_SA_INSTALLED:
        ipsec_control_sa_event_installed(ipsec_sa);
        break;

    case IPSEC_CONTROL_SA_FIRST_PACKET_RECEIVED:

        IPSEC_SA_DEBUG(LOW, ipsec_sa, "First packet received.");
        {
            struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;

            ipsec_sa->first_packet_received = true;

            if (ipsec_sa->params.rekey == false)
            {
                break;
            }

            if (ipsec_sa->params.initiator == true &&
                ipsec_sa->params.ikev1_sa == true)
            {
                struct IPsecSa *old_sa =
                    ipsec_control_db_sa_lookup(
                            ipsec_control,
                            ipsec_sa->params.rekeyed_inbound_spi);

                if (old_sa != NULL &&
                    old_sa->timeout_event == IPSEC_CONTROL_SA_REKEY_DELETE)
                {
                    int deletion_timeout =
                      ipsec_control->ipsec_life_rekey_delete_short_delay;
                    int life_left = ipsec_control_sa_life_left(old_sa);

                    if (life_left > deletion_timeout)
                    {
                        ipsec_control_sa_timeout_register(
                                old_sa,
                                IPSEC_CONTROL_SA_REKEY_DELETE,
                                deletion_timeout);
                    }
                }
            }

            if (ipsec_sa->outbound_installed == false &&
                ipsec_sa->ikev2_simultaneous_rekey !=
                IPSEC_CONTROL_IKEV2_REKEY_LOSER)
            {
                ipsec_control_data_plane_install_outbound(
                        ipsec_sa);
            }
        }
        break;

    case IPSEC_CONTROL_SA_IDLE_TIMEOUT:

        IPSEC_SA_DEBUG(LOW, ipsec_sa, "Idle timeout.");

        ipsec_control_sa_idle_timeout(ipsec_sa);

        break;

    case IPSEC_CONTROL_SA_REKEY:

        IPSEC_SA_DEBUG(LOW, ipsec_sa, "Rekey.");

        ipsec_control_initiate_rekey(ipsec_sa);

        break;

    case IPSEC_CONTROL_SA_DELETE:

        IPSEC_SA_DEBUG(LOW, ipsec_sa, "Deletion.");

        ipsec_control_initiate_deletion(ipsec_sa);

        break;

    case IPSEC_CONTROL_SA_REKEY_DELETE:

        IPSEC_SA_DEBUG(LOW, ipsec_sa, "Rekey delete.");

        ipsec_control_initiate_deletion(ipsec_sa);

        break;

    case IPSEC_CONTROL_SA_EXPIRE:

        IPSEC_SA_DEBUG(LOW, ipsec_sa, "Expired.");

        ipsec_control_initiate_deletion(ipsec_sa);

        break;

    case IPSEC_CONTROL_SA_SEQUENCE_NUMBER_OVERFLOW:

        IPSEC_SA_DEBUG(LOW, ipsec_sa, "Sequence number overflow.");

        ipsec_control_initiate_deletion(ipsec_sa);

        break;

    case IPSEC_CONTROL_SA_DESTROY:

        IPSEC_SA_DEBUG(LOW, ipsec_sa, "Destroyed.");

        ipsec_control_sa_uninstall(ipsec_sa);

        deleted = true;

        break;

    default:
        SSH_NOTREACHED;
        break;
    }

    if (deleted == false)
    {
        ASSERT(ipsec_sa->timeout_registered != false);
    }
}


static void
ipsec_control_sa_sshtimeoutcallback(
        void *param)
{
    struct IPsecSa *ipsec_sa = param;
    IPsecControlSaEvents event = ipsec_sa->timeout_event;

    ipsec_sa->timeout_registered = false;
    ipsec_sa->timeout_event = IPSEC_CONTROL_SA_NONE;

    ipsec_control_sa_expire_timeout_register(
            ipsec_sa,
            ipsec_sa->life_to_live);

    ipsec_control_sa_handle_event(ipsec_sa, event);
}


static void
ipsec_control_sa_set_rekey_timer(
        struct IPsecSa *ipsec_sa)
{
    int rekey_timeout;
    int rekey_jitter;
    int life_left = ipsec_control_sa_life_left(ipsec_sa);
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;

    if (ipsec_sa->rekey_attempt == 0)
    {
        ASSERT(life_left >=
               IPSEC_LIFE_BEFORE_REKEY_MIN + IPSEC_LIFE_AFTER_REKEY_MIN);

        rekey_timeout = life_left - IPSEC_LIFE_AFTER_REKEY_MIN;

        {
            int retry_timeout = rekey_timeout;

            retry_timeout =
                percent_of(
                        IPSEC_LIFE_REKEY_RETRY_PERCENTAGE,
                        retry_timeout);

            retry_timeout =
                max_int(
                        IPSEC_LIFE_REKEY_RETRY_MIN,
                        retry_timeout);

            ipsec_sa->rekey_retry_timeout = retry_timeout;
        }

        if (ipsec_sa->params.initiator == true)
        {
            rekey_timeout =
                percent_of(
                        IPSEC_LIFE_INITIATOR_REKEY_PERCENTAGE,
                        rekey_timeout);
        }
        else
        {
            rekey_timeout =
                percent_of(
                        IPSEC_LIFE_RESPONDER_REKEY_PERCENTAGE,
                        rekey_timeout);
        }
    }
    else
    {
        rekey_timeout = ipsec_sa->rekey_retry_timeout;
    }

    rekey_jitter =
        calculate_jitter(
                ipsec_control,
                IPSEC_LIFE_REKEY_JITTER_PERCENTAGE,
                rekey_timeout);

    rekey_timeout -= rekey_jitter;

    if (rekey_timeout + IPSEC_LIFE_DELETE_THRESHOLD < life_left)
    {
        ipsec_sa->life_to_live = life_left - rekey_timeout;

        ipsec_control_sa_timeout_register(
                ipsec_sa,
                IPSEC_CONTROL_SA_REKEY,
                rekey_timeout);

        IPSEC_SA_DEBUG(
                MEDIUM,
                ipsec_sa,
                "Rekey timeout %d, life to live %d, %d attempts.",
                rekey_timeout,
                ipsec_sa->life_to_live,
                ipsec_sa->rekey_attempt);
    }
    else
    {
        IPSEC_SA_DEBUG(
                MEDIUM,
                ipsec_sa,
                "Rekey timer not set. Setting expire with life left %d.",
                life_left);

        ipsec_control_sa_expire_timeout_register(ipsec_sa, life_left);
    }
}


static void
ipsec_control_sa_event_installed(
        struct IPsecSa *ipsec_sa)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;

    IPSEC_SA_DEBUG(LOW, ipsec_sa, "Installed.");

    ipsec_control_sa_set_rekey_timer(ipsec_sa);

    if (ipsec_sa->ikev2_simultaneous_rekey ==
        IPSEC_CONTROL_IKEV2_REKEY_WINNER)
    {
        ipsec_sa_responder_simultaneous_lost(
                ipsec_control,
                ipsec_sa->ikev2_simultaneous_inbound_spi);
    }

    if (ipsec_sa->ikev2_simultaneous_rekey ==
        IPSEC_CONTROL_IKEV2_REKEY_LOSER)
    {
        ipsec_sa_responder_simultaneous_won(
                ipsec_control,
                ipsec_sa->ikev2_simultaneous_inbound_spi);

        ipsec_control_sa_rekeyed(
                ipsec_sa,
                true);
    }
    else
    if (ipsec_sa->ikev2_simultaneous_rekey ==
        IPSEC_CONTROL_IKEV2_REKEY_ONGOING)
    {
        IPSEC_SA_DEBUG(
                HIGH,
                ipsec_sa,
                "Simultaneous rekey ongoing with SPI %08x.",
                (int) ipsec_sa->ikev2_simultaneous_inbound_spi);
    }
    else
    if (ipsec_sa->params.rekey == true)
    {
        bool quick_delete = ipsec_sa->params.initiator;

        if (ipsec_sa->params.ikev1_sa == true)
        {
            /* IKEv1 has three packet exchange for rekeys; so
               responder does quick delete.*/

            quick_delete = !quick_delete;
        }

        ipsec_control_sa_rekeyed_spi(
                ipsec_control,
                ipsec_sa->params.rekeyed_inbound_spi,
                quick_delete);
    }

    (*ipsec_control->event_callback)(
            ipsec_control->param,
            &ipsec_sa->params,
            &ipsec_sa->endpoints,
            IPSEC_SA_EVENT_INSTALL);
}


static void
ipsec_control_data_plane_remove(
        struct IPsecSa *ipsec_sa)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;

    if (ipsec_control->control_callbacks != NULL &&
        ipsec_control->control_callbacks->remove_sa_cb != NULL)
    {
        ipsec_control->control_callbacks->remove_sa_cb(
                ipsec_control->control_param,
                &ipsec_sa->params,
                &ipsec_sa->endpoints,
                ipsec_sa->control_sa);
    }
}


static void
ipsec_control_sa_uninstall(
        struct IPsecSa *ipsec_sa)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;

    ASSERT(ipsec_sa->pending != true);

    if (ipsec_sa->params.rekeyed == true)
    {
        struct IPsecSa *chain_sa;

        uint32_t rekeyed_spi = ipsec_sa->params.inbound_spi;

        IPSEC_SA_CIRCLE_FOR_OTHERS(chain_sa, ipsec_sa)
        {
            if (chain_sa->params.rekeyed_inbound_spi == rekeyed_spi &&
                chain_sa->pending == false &&
                chain_sa->outbound_installed == false &&
                chain_sa->ikev2_simultaneous_rekey !=
                IPSEC_CONTROL_IKEV2_REKEY_LOSER)
            {
                ipsec_control_data_plane_install_outbound(
                        chain_sa);
            }
        }
    }

    if (ipsec_sa->params.initiator == true &&
        ipsec_sa->ikev2_simultaneous_rekey ==
        IPSEC_CONTROL_IKEV2_REKEY_ONGOING)
    {
        ipsec_sa_responder_simultaneous_won(
                ipsec_control,
                ipsec_sa->ikev2_simultaneous_inbound_spi);
    }

    if (ipsec_control_sa_circle_is_empty(ipsec_sa) == true)
    {
        ipsec_sa->params.last = true;
    }

    ipsec_control_data_plane_remove(
            ipsec_sa);

    (*ipsec_control->event_callback)(
            ipsec_control->param,
            &ipsec_sa->params,
            &ipsec_sa->endpoints,
            IPSEC_SA_EVENT_UNINSTALL);

    ipsec_control_sa_timeout_cancel(ipsec_sa);
    ipsec_control_sa_free(ipsec_sa);
}


static void
ipsec_control_tunnel_disconnect(
        struct IPsecSa *ipsec_sa)
{
    if (ipsec_sa->params.rekeyed == false)
    {
        (*ipsec_sa->ipsec_control->event_callback)(
                ipsec_sa->ipsec_control->param,
                &ipsec_sa->params,
                &ipsec_sa->endpoints,
                IPSEC_SA_EVENT_EXPIRE);
    }
}


static void
ipsec_control_initiate_deletion(
        struct IPsecSa *ipsec_sa)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;
    unsigned int delete_timeout;

    ipsec_sa->life_to_live = 0;
    delete_timeout = ipsec_control_sa_life_left(ipsec_sa);
    delete_timeout = min_int(delete_timeout, IPSEC_LIFE_DELETE_THRESHOLD);

    ipsec_control_sa_timeout_register(
            ipsec_sa,
            IPSEC_CONTROL_SA_DESTROY,
            delete_timeout);

    ipsec_control_tunnel_disconnect(ipsec_sa);

    ipsec_sa->deleted = true;

    if (ipsec_sa->delete_sent)
    {
        IPSEC_SA_DEBUG(
                FAIL,
                ipsec_sa,
                "Delete already sent.");
        return;
    }

    if (ipsec_sa->delete_received)
    {
        IPSEC_SA_DEBUG(
                MEDIUM,
                ipsec_sa,
                "Delete already received.");
        return;
    }

    IPSEC_SA_DEBUG(LOW,
                   ipsec_sa,
                   "Sending delete event.");

    (*ipsec_control->event_callback)(
            ipsec_control->param,
            &ipsec_sa->params,
            &ipsec_sa->endpoints,
            IPSEC_SA_EVENT_DELETE);

    ipsec_sa->delete_sent = true;
}


static void
ipsec_control_sa_destroy(
        struct IPsecSa *ipsec_sa)
{
    ipsec_control_tunnel_disconnect(ipsec_sa);

    ipsec_control_sa_handle_event(ipsec_sa, IPSEC_CONTROL_SA_DESTROY);
}


static bool
ipsec_control_sa_rekey_possible(
        struct IPsecSa *ipsec_sa)
{
    if (ipsec_sa->params.rekeyed == true)
    {
        IPSEC_SA_DEBUG(
                LOW,
                ipsec_sa,
                "Rekey not possible; Already rekeyed.");

        return false;
    }

    if (ipsec_control_sa_rekey_ongoing(ipsec_sa) == true)
    {
        IPSEC_SA_DEBUG(
                LOW,
                ipsec_sa,
                "Rekey not possible; Already ongoing.");

        return false;
    }

    if (ipsec_sa->ikev2_simultaneous_rekey ==
        IPSEC_CONTROL_IKEV2_REKEY_LOSER)
    {
        IPSEC_SA_DEBUG(
                MEDIUM,
                ipsec_sa,
                "Rekey not possible; Simultaneous loser.");

        return false;
    }

    /* Check if the SPI is already being rekeyed. */
    {
        struct IPsecSa *chain_sa;

        IPSEC_SA_CIRCLE_FOR_OTHERS(chain_sa, ipsec_sa)
        {
            if (chain_sa->params.rekeyed_inbound_spi ==
                ipsec_sa->params.inbound_spi)
            {
                IPSEC_SA_DEBUG(
                        MEDIUM,
                        ipsec_sa,
                        "Rekey not possible; Already negotiating.");

                return false;
            }
        }
    }

    /* Check if SA is already deleted. */
    if (ipsec_sa->deleted == true)
    {
        IPSEC_SA_DEBUG(
                MEDIUM,
                ipsec_sa,
                "Rekey not possible; Already deleted.");

        return false;
    }

    IPSEC_SA_DEBUG(
            LOW,
            ipsec_sa,
            "Rekey is possible.");

    return true;
}


static void
ipsec_control_initiate_rekey(
        struct IPsecSa *ipsec_sa)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;
    bool rekey_possible;

    rekey_possible = ipsec_control_sa_rekey_possible(ipsec_sa);

    if (rekey_possible == false)
    {
        IPSEC_SA_DEBUG(
                MEDIUM,
                ipsec_sa,
                "Rekey not initiated.");
    }
    else
    {
        IPSEC_SA_DEBUG(
                MEDIUM,
                ipsec_sa,
                "Initiating rekey; attempt %d",
                ipsec_sa->rekey_attempt);

        (*ipsec_control->event_callback)(
                ipsec_control->param,
                &ipsec_sa->params,
                &ipsec_sa->endpoints,
                IPSEC_SA_EVENT_REKEY);
    }
}


static bool
ipsec_control_sa_allocate(
        struct IPsecControl *ipsec_control,
        struct IPsecSa **ipsec_sa_p,
        uint32_t inbound_spi)
{
    struct IPsecSa *ipsec_sa = NULL;
    bool status = true;

    if (status == true)
    {
        ipsec_sa = ssh_calloc(1, sizeof *ipsec_sa);
        if (!ipsec_sa)
        {
            IPSEC_CONTROL_DEBUG(
                    FAIL,
                    ipsec_control,
                    "Out of memory while allocating IPsec SA!");

            status = false;
        }
    }

    if (status == true)
    {
        ipsec_sa->pending = true;
        ipsec_sa->params.inbound_spi = inbound_spi;
        ipsec_sa->params.event_id = inbound_spi;

        ipsec_sa->ipsec_control = ipsec_control;

        ipsec_control_db_sa_insert(
                ipsec_control,
                ipsec_sa);


        IPSEC_SA_DEBUG(
                LOW,
                ipsec_sa,
                "Allocated IPsec SA 0x%p.",
                ipsec_sa);
    }

    if (ipsec_sa_p != NULL)
    {
        *ipsec_sa_p = ipsec_sa;
    }

    return status;
}


static void
ipsec_control_sa_free(
        struct IPsecSa *ipsec_sa)
{
    struct IPsecSaParams *ipsec_sa_params = &ipsec_sa->params;

    IPSEC_SA_DEBUG(
            LOW,
            ipsec_sa,
            "Freeing IPsec SA 0x%p.",
             ipsec_sa);

    if (ipsec_control_db_sa_lookup_by_chain_id(
                ipsec_sa->ipsec_control,
                ipsec_sa->chain_id)
        == ipsec_sa)
    {
        ipsec_control_db_sa_remove_chain_id(
                ipsec_sa->ipsec_control,
                ipsec_sa);

        if (ipsec_sa->circle_next != ipsec_sa)
        {
            ipsec_control_db_sa_insert_chain_id(
                    ipsec_sa->ipsec_control,
                    ipsec_sa->circle_next);
        }
    }

    ipsec_control_sa_circle_unlink(ipsec_sa);

    ipsec_control_db_sa_remove(
            ipsec_sa->ipsec_control,
            ipsec_sa);

    ASSERT(ipsec_sa->timeout_registered == false);

    if (ipsec_sa_params->selector_group != NULL)
    {
        ssh_free(ipsec_sa_params->selector_group);
        ipsec_sa_params->selector_group = NULL;
    }

    if (ipsec_sa->ipsec_sa_keymaterial != NULL)
    {
        ssh_free(ipsec_sa->ipsec_sa_keymaterial);
        ipsec_sa->ipsec_sa_keymaterial = NULL;
    }

    ssh_free(ipsec_sa);
}


static void
ipsec_control_sa_log_event(
        IPsecControlSaEvents event,
        struct IPsecSa *ipsec_sa)
{
    SshLogFacility facility;
    SshLogSeverity severity;
    char *proto_str = "ESP";
    char *event_str = NULL;

    facility = ipsec_sa->params.log_facility;
    severity = SSH_LOG_INFORMATIONAL;

    if (ipsec_sa->params.ipproto == SSH_IPPROTO_AH)
    {
        proto_str = "AH ";
    }

    switch (event)
    {
    case IPSEC_CONTROL_SA_INSTALLED:
        event_str = "installed";
        break;

    case IPSEC_CONTROL_SA_FIRST_PACKET_RECEIVED:
        event_str = "first packet received";
        break;

    case IPSEC_CONTROL_SA_IDLE_TIMEOUT:
        event_str = "idle timeout";
        break;

    case IPSEC_CONTROL_SA_REKEY:
        event_str = "rekey start";
        break;

    case IPSEC_CONTROL_SA_DELETE:
        event_str = "deleted";
        break;

    case IPSEC_CONTROL_SA_REKEY_DELETE:
        event_str = "obsoleted";
        break;

    case IPSEC_CONTROL_SA_EXPIRE:
        event_str = "expired";
        break;

    case IPSEC_CONTROL_SA_SEQUENCE_NUMBER_OVERFLOW:
        event_str = "sequence number overflow";
        break;

    case IPSEC_CONTROL_SA_DESTROY:
        event_str = "destroyed";
        break;

    default:
        SSH_NOTREACHED;
        break;
    }

    if (event_str != NULL)
    {
        ssh_log_event(facility, severity, "IPsec SA EVENT:");
        ssh_log_event(
                facility,
                severity,
                "        IPsec SA %s Inbound SPI %08lx, "
                "Outbound SPI %08lx: %s",
                proto_str,
                (unsigned long) ipsec_sa->params.inbound_spi,
                (unsigned long) ipsec_sa->params.outbound_spi,
                event_str);
    }
}

/**
   Functions handling data plane IPsec SAs.
 */

static void
ipsec_control_sa_event_handle_event(
        struct IPsecSa *ipsec_sa,
        bool overflow,
        bool first_packet,
        bool rekey,
        bool idle_timeout)
{
    if (overflow == true)
    {
        ipsec_control_sa_handle_event(
                ipsec_sa,
                IPSEC_CONTROL_SA_SEQUENCE_NUMBER_OVERFLOW);
        return;
    }

    if (first_packet == true)
    {
        ipsec_control_sa_handle_event(
                ipsec_sa,
                IPSEC_CONTROL_SA_FIRST_PACKET_RECEIVED);
    }

    if (rekey == true)
    {
        ipsec_control_sa_handle_event(ipsec_sa, IPSEC_CONTROL_SA_REKEY);
    }

    if (idle_timeout == true)
    {
        ipsec_control_sa_handle_event(ipsec_sa, IPSEC_CONTROL_SA_IDLE_TIMEOUT);
    }
}

static void
ipsec_control_sa_idle_timeout(
        struct IPsecSa *ipsec_sa)
{
    struct IPsecControl *ipsec_control = ipsec_sa->ipsec_control;

    IPSEC_SA_DEBUG(
                HIGH,
                ipsec_sa,
                "Sending idle event.");

    (*ipsec_control->event_callback)(
            ipsec_control->param,
            &ipsec_sa->params,
            &ipsec_sa->endpoints,
            IPSEC_SA_EVENT_IDLE);
}


void
ipsec_control_sa_event(
        struct IPsecControl *ipsec_control,
        uint32_t event_id,
        uint32_t spi,
        bool overflow,
        bool first_packet,
        bool rekey,
        bool idle_timeout)
{
    struct IPsecSa *ipsec_sa_found = NULL;
    struct IPsecSa *ipsec_sa_first;
    uint32_t chain_id = event_id & IPSEC_CONTROL_SA_SPI_MASK;

    ipsec_sa_first =
        ipsec_control_db_sa_lookup_by_chain_id(
                ipsec_control,
                chain_id);

    if (ipsec_sa_first != NULL)
    {
        struct IPsecSa *ipsec_sa = ipsec_sa_first;

        do
        {
            if (ipsec_sa->params.event_id_inbound == event_id &&
                ipsec_sa->params.inbound_spi == spi)
            {
                ipsec_sa_found = ipsec_sa;
                break;
            }

            if (ipsec_sa->params.event_id_outbound == event_id &&
                ipsec_sa->params.outbound_spi == spi)
            {
                ipsec_sa_found = ipsec_sa;
                break;
            }

            ipsec_sa = ipsec_sa->circle_next;
        }
        while (ipsec_sa != ipsec_sa_first);
    }

    if (ipsec_sa_found != NULL)
    {
        ipsec_control_sa_event_handle_event(
                ipsec_sa_found,
                overflow,
                first_packet,
                rekey,
                idle_timeout);
    }
}

void
ipsec_control_unknown_spi_event(
        void *control_p,
        const struct InAddr *local_address,
        const struct InAddr *remote_address,
        int local_port,
        int remote_port,
        int protocol,
        uint32_t spi,
        int routing_instance_id)
{
    struct IPsecControl *ipsec_control = control_p;

    if (ipsec_control->unknown_spi_callback != NULL)
    {
        ipsec_control->unknown_spi_callback(
                ipsec_control->param,
                local_address,
                remote_address,
                local_port,
                remote_port,
                protocol,
                spi,
                routing_instance_id);
    }
}

const struct IPsecSaParams *
ipsec_sa_first_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle)
{
    const struct IPsecSaParams *ipsec_sa_params = NULL;
    struct IPsecSa *ipsec_sa;

    ipsec_sa =
        ipsec_control_db_sa_lookup_first_by_peer_handle(
                ipsec_control,
                peer_handle);

    if (ipsec_sa != NULL)
    {
        ipsec_sa_params = &ipsec_sa->params;
    }

    return ipsec_sa_params;
}

const struct IPsecSaParams *
ipsec_sa_next_by_peer_handle(
        struct IPsecControl *ipsec_control,
        uint32_t peer_handle,
        uint32_t inbound_spi)
{
    const struct IPsecSaParams *ipsec_sa_params = NULL;
    struct IPsecSa *ipsec_sa;

    ipsec_sa =
        ipsec_control_db_sa_lookup_next_by_peer_handle(
                ipsec_control,
                peer_handle,
                inbound_spi);

    if (ipsec_sa != NULL)
    {
        ipsec_sa_params = &ipsec_sa->params;
    }

    return ipsec_sa_params;
}
