/**
   @copyright
   Copyright (c) 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Base policy functions.
*/

#ifndef IPSEC_BASE_POLICY_H
#define IPSEC_BASE_POLICY_H

/** Set SPD system policy. */
bool
ipsec_system_policy_set(struct IPsecControl *ipsec_control, bool is_responder);

/** Clear SPD system policy. */
void
ipsec_system_policy_clear(struct IPsecControl *ipsec_control);

/** Set SPD base policy. */
bool
ipsec_base_policy_set(struct IPsecControl *ipsec_control, bool discard);

/** Clear SPD base policy. */
void
ipsec_base_policy_clear(struct IPsecControl *ipsec_control);

#endif /* IPSEC_BASE_POLICY_H */
