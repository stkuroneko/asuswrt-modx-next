/**
   @copyright
   Copyright (c) 2004 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   SAD handle structure.
*/

#ifndef PM_IKE_SAD_H
#define PM_IKE_SAD_H

#include "sshincludes.h"
#include "sshadt.h"
#include "sshadt_list.h"
#include "sshikev2-payloads.h"
#include "quicksecpm_internal.h"
#include "ipsec_sa.h"


struct SshSADHandleRec {
  SshADTContainer ts_free_list;
  SshADTContainer sa_free_list;
  SshADTContainer conf_free_list;

  SshADTContainer ike_sa_by_spi;

  /** Back pointer to the policymanager */
  SshPm pm;
};

typedef struct SshSADHandleRec  SshSADHandleStruct;

void
ssh_pm_ipsec_sa_event_unknown_spi_cb(
        void *param,
        const struct InAddr *local_ip,
        const struct InAddr *remote_ip,
        uint16_t local_port,
        uint16_t remote_port,
        SshInetIPProtocolID ipproto,
        uint32_t spi,
        int routing_instance_id);

void
ssh_pm_ipsec_sa_event_cb(
        void *param,
        const struct IPsecSaParams *ipsec_sa_params,
        const struct IPsecSaEndpoints *ipsec_sa_endpoints,
        IPsecSaEvent event);


#endif /* PM_IKE_SAD_H */
