/**
   @copyright
   Copyright (c) 2015 - 2016, INSIDE Secure Oy. All rights reserved.
*/


#ifndef IPSEC_CONTROL_INIT_H
#define IPSEC_CONTROL_INIT_H

#include "public_defs.h"

struct IPsecControl;

bool
ipsec_control_init(
        struct IPsecControl **ipsec_control_p);

void
ipsec_control_flush(
        struct IPsecControl *ipsec_control);

void
ipsec_control_uninit(
        struct IPsecControl **ipsec_control_p);

#endif /* IPSEC_CONTROL_INIT_H */
