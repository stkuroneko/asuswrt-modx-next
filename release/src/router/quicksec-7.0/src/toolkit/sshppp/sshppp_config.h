/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_CONFIG_H

#define SSH_PPP_CONFIG_H 1

/* Macros are used instead of enums to save space
   (significantly, actually). */

#define SSH_PPP_CONFIG_STATUS_UNINIT 0
#define SSH_PPP_CONFIG_STATUS_REJECTED 1
#define SSH_PPP_CONFIG_STATUS_ACK 2
#define SSH_PPP_CONFIG_STATUS_NAK 3
#define SSH_PPP_CONFIG_STATUS_QUERY 4
#define SSH_PPP_CONFIG_STATUS_NAK_PROMPT 5

#define SSH_PPP_CONFIG_VAL_UNSET 0
#define SSH_PPP_CONFIG_VAL_SET 1

#define SSH_PPP_CONFIG_PREF_MANDATORY 3
#define SSH_PPP_CONFIG_PREF_PREFER 2
#define SSH_PPP_CONFIG_PREF_REJECT 1
#define SSH_PPP_CONFIG_PREF_DEFAULT 0

/* Flags for authentication option */

#define SSH_PPP_AUTH_F_CHAP_OK 1
#define SSH_PPP_AUTH_F_EAP_OK 2
#define SSH_PPP_AUTH_F_PAP_OK 4
#define SSH_PPP_AUTH_F_MSCHAPv1_OK 8
#define SSH_PPP_AUTH_F_MSCHAPv2_OK 16

typedef uint8_t SshPppConfigStatus;
typedef uint8_t SshPppConfigValueStatus;
typedef uint8_t SshPppConfigPreference;

/* A simple 32-bit integer value */

typedef struct
{
    uint32_t value;
} SshLCPConfigOptionValueInt32Struct;

/* The size of all counters used in the PPP library */

typedef uint8_t SshPppCounter;

typedef struct
{
    uint32_t host_address;
} SshIPCPConfigOptionValueIPv4Struct;

typedef struct
{
    uint32_t net_address;
    uint32_t mask;
    unsigned int constraint_initialized:1;
} SshIPCPConfigOptionValueIPv4ConstraintStruct;

/* Currently we only support EAP and CHAP, and hence we
   only need one byte of auth data */

#define SSH_PPP_AUTH_DATA_MAX 1

typedef struct
{
    uint16_t protocol;
    uint8_t datalen;
    uint8_t data[SSH_PPP_AUTH_DATA_MAX];
} SshLCPConfigOptionValueAuth;

typedef enum {
  SSH_LCP_ACK,
  SSH_LCP_REJ,
  SSH_LCP_NAK,
  SSH_LCP_NONE,
  SSH_LCP_FATAL
} SshPppConfigResponse;

#define MAX_OPTIONS

struct SshPppConfigOptionRec;
typedef struct SshPppConfigOptionRec *SshPppConfigOption;

/* Simple interface each PPP Configuration option must implement */

/* Function which checks if an option on-the-wire  represents the
   same value held by the instance opt */

typedef bool (*SshPppConfigOptionIsMarshalCB)(SshPppConfigOption opt,
                                                 SshPppPktBuffer pkt);

/* Function which determines if an option value on-the-wire
   is preferable to the value currently held by the instance. */

typedef bool (*SshPppConfigOptionIsPrefCB)(SshPppConfigOption opt,
                                              SshPppPktBuffer pkt);

/* Function which determines if two instances contain
   equal values for the option */

typedef bool (*SshPppConfigOptionIsEqualCB)(SshPppConfigOption opt,
                                               SshPppConfigOption opt2);

/* Determines if an on-the-wire representation of an
   option value is legitimate */
typedef SshPppConfigResponse (*SshPppConfigOptionIsOkCB)(SshPppConfigOption o,
                                                         SshPppPktBuffer pkt);

/* Parses the on-the-wire syntax of the option into the
   option value */
typedef void (*SshPppConfigOptionUnmarshalCB)(SshPppConfigOption o,
                                              SshPppPktBuffer pkt);

/* Builds an on-the-wire syntax of the option value */
typedef unsigned long (*SshPppConfigOptionMarshalCB)(SshPppConfigOption opt,
                                                     SshPppPktBuffer pkt);

/* Uninit the structure */
typedef void (*SshPppConfigOptionUninitCB)(SshPppConfigOption opt);

typedef struct SshPppConfigOptionImplRec
{
    /* Type of this option. Also the option id */
    uint8_t type;

    SshPppConfigOptionIsMarshalCB iseq;
    SshPppConfigOptionIsPrefCB ispref;
    SshPppConfigOptionIsEqualCB equals;
    SshPppConfigOptionIsOkCB isok;
    SshPppConfigOptionUnmarshalCB unmarshal;
    SshPppConfigOptionMarshalCB marshal;
    SshPppConfigOptionUninitCB uninit;
} SshPppConfigOptionImplStruct, *SshPppConfigOptionImpl;

#define SSH_PPP_CONFIG_VALUE_STATUS(x) ((x) & 0xF)
#define SSH_PPP_CONFIG_NEGOTIATION_STATUS(x) (((x) >> 4) & 0xF)
#define SSH_PPP_CONFIG_STATUS(x,y) ((((x) & 0xF) << 4) | ((y) & 0x0F))

typedef struct SshPppConfigOptionRec
{
    /* Option specific information, either a 32-bit flag
       field or a pointer to option specific data */
    union {
      void *ptr;
      uint32_t flags;
      struct {
        uint16_t min;
        uint16_t max;
      } bound;
    } ctx;

    /* Array of size max_idx */

    void *option;

    /* In the status  array the value status (set / unset)
       and negotiation status of each round is packed into
       one byte */
    uint8_t *status;

    /* Pointer to the actual implementation of all abstract
       methods. */
    SshPppConfigOptionImpl impl;

    /* Preference we have when negotiating this option */
    SshPppConfigPreference preference;

    /* Index in the ring buffer containing current and
       past values */
    uint8_t current_idx;
    uint8_t max_idx;

    /* A counter for use by the caller. Used to record
       how many times negotiation of this parameter
       has been unsuccessfully attempted. */
    SshPppCounter counter;

} SshPppConfigOptionStruct;

/* Prototypes */

void
ssh_ppp_config_option_set_counter(SshPppConfigOption opt,
                                  SshPppCounter counter_val);

SshPppCounter
ssh_ppp_config_option_get_counter(SshPppConfigOption opt);

void
ssh_ppp_config_option_inc_counter(SshPppConfigOption opt);

void
ssh_ppp_config_preference_set(SshPppConfigOption opt,
                              SshPppConfigPreference pref_val);

SshPppConfigPreference
ssh_ppp_config_preference_get(SshPppConfigOption opt);

/* Three simple stub functions which merely return SSH_LCP_NAK,
   SSH_LCP_AC or SSH_LCP_REJ */

SshPppConfigPreference
ssh_ppp_config_option_nak(SshPppPktBuffer pkt);

SshPppConfigPreference
ssh_ppp_config_option_ack(SshPppPktBuffer pkt);

SshPppConfigPreference
ssh_ppp_config_option_rej(SshPppPktBuffer pkt);

/* Functions for hiding the actual option implementations */

unsigned long
ssh_ppp_config_option_marshal(SshPppConfigOption opt,
                              SshPppPktBuffer pkt);


unsigned long
ssh_ppp_config_option_marshal_all(SshPppConfigOption opt,
                                  SshPppPktBuffer pkt);


int
ssh_ppp_config_option_isnakable(SshPppConfigOption opt);

void
ssh_ppp_config_option_unmarshal(SshPppConfigOption opt,
                                SshPppPktBuffer pkt);

uint32_t
ssh_ppp_config_option_basic_read(SshPppPktBuffer pkt);


void
ssh_ppp_config_option_uninit(SshPppConfigOption opt);

bool
ssh_ppp_config_option_init_mru(SshPppConfigOption val,
                               uint8_t max_iters);

void
ssh_ppp_config_option_mru_set_constraint(SshPppConfigOption opt,
                                         uint16_t min,
                                         uint16_t max);
bool
ssh_ppp_config_option_init_auth(SshPppConfigOption opt,
                                uint8_t max_iters);

bool
ssh_ppp_config_option_init_quality(SshPppConfigOption opt,
                                   uint8_t max_iters);

bool
ssh_ppp_config_option_init_magic(SshPppConfigOption opt,
                                 uint8_t max_iters);

bool
ssh_ppp_config_option_init_ipv4(SshPppConfigOption opt,
                                uint8_t type,
                                uint8_t max_iters);

void
ssh_ppp_config_option_ipv4_set_ip(SshPppConfigOption opt, uint32_t value);

void
ssh_ppp_config_option_ipv4_set_constraint(SshPppConfigOption opt,
                                          uint32_t addr, uint32_t mask);
void
ssh_ppp_config_option_ipv4_unset_constraint(SshPppConfigOption opt);

bool
ssh_ppp_config_option_init_pfc(SshPppConfigOption opt,
                               uint8_t max_iters);
bool
ssh_ppp_config_option_init_acfc(SshPppConfigOption opt,
                                uint8_t max_iters);

bool
ssh_ppp_config_option_init_accm(SshPppConfigOption opt,
                                uint8_t max_iters);

void
ssh_ppp_config_option_int32_set(SshPppConfigOption opt,uint32_t value);

uint32_t
ssh_ppp_config_option_int32_get_value(SshPppConfigOption opt);

SshIPCPConfigOptionValueIPv4Struct*
ssh_ppp_config_option_get_optionvalue_ipv4(SshPppConfigOption opt);

SshLCPConfigOptionValueInt32Struct*
ssh_ppp_config_option_get_optionvalue_int32(SshPppConfigOption opt);

SshLCPConfigOptionValueAuth*
ssh_ppp_config_option_get_optionvalue_auth(SshPppConfigOption opt);

SshPppConfigStatus
ssh_ppp_config_option_get_status(SshPppConfigOption opt);

void
ssh_ppp_config_option_set_status(SshPppConfigOption opt,
                                 SshPppConfigStatus status);

void
ssh_ppp_config_option_set_value_status(SshPppConfigOption opt,
                                       SshPppConfigValueStatus status);

SshPppConfigValueStatus
ssh_ppp_config_option_get_value_status(SshPppConfigOption opt);

void
ssh_ppp_config_option_push(SshPppConfigOption opt);

void
ssh_ppp_config_option_pop(SshPppConfigOption opt);

int
ssh_ppp_config_option_isack(SshPppConfigOption opt);

int
ssh_ppp_config_option_isquery(SshPppConfigOption opt);

SshPppConfigResponse
ssh_ppp_config_option_isok(SshPppConfigOption opt, SshPppPktBuffer pkt);

bool
ssh_ppp_config_option_cmp(SshPppConfigOption opt, SshPppPktBuffer pkt);

bool
ssh_ppp_config_option_ispref(SshPppConfigOption opt, SshPppPktBuffer pkt);

void
ssh_ppp_config_option_auth_set(SshPppConfigOption opt,
                               uint16_t protocol,
                               uint8_t *buf,
                               unsigned long len);

uint16_t
ssh_ppp_config_option_auth_get_protocol(SshPppConfigOption opt);

uint8_t
ssh_ppp_config_option_auth_chap_get_algorithm(SshPppConfigOption opt);

void
ssh_ppp_config_option_auth_accept(SshPppConfigOption opt,
                                  SshPppAuthType auth_type);

uint8_t
ssh_ppp_config_option_get_type(SshPppConfigOption opt);

void
ssh_ppp_config_option_reset(SshPppConfigOption opt);

#endif /* SSH_PPP_CONFIG_H */
