/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Top-level policy management API for the IPsec implementation.
   (This header file consists of include directives.)
*/

#ifndef VPN_PM_H
#define VPN_PM_H

#include "ipsec_params.h"
#include "sshinet.h"
#include "sshcrypt.h"
#include "ip_interfaces.h"
#include "sshaudit.h"

/** Core Quicksec policy manager API */
#include "core_pm.h"

/** IPSec related Quicksec policy manager API */
#include "ipsec_pm.h"

/** Low-level policy management API for IPsec implementation. */
#include "ipsec_pm_low.h"

#endif /* VPN_PM_H */
