/**
   @copyright
   Copyright (c) 2005 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
    SPI management for IPSec SA's.

    The SPI's for dynamically keyed (via. IKE) SA's are
    managed together. Inbound SPI's are always unique across different
    IP protocols (i.e. the value of an inbound ESP SPI is never equal to
    the value of an inbound AH SPI). Inbound SPI values are registered to
    the ADT container pm->inbound_spis. Outbound SPI's for IKE SA's are
    stored in the pm->spi_out_hash hash table. The remote IP address,
    remote IKE port and IP protocol is also stored in the mapping.
    This mapping is used for handling IPSec delete notifications.
*/

#include "sshincludes.h"
#include "sshadt.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "PmIkeSPI"

/************************ Outbound SPI lookup *******************************/

static SshPmSpiOut
ssh_pm_lookup_outbound_spi_by_inbound_spi(
        SshPm pm,
        uint32_t outbound_spi,
        uint32_t inbound_spi)
{
    SSH_DEBUG(SSH_D_LOWOK,
              ("SPI lookup for outbound SPI 0x%08lx, inbound SPI 0x%08lx",
               (unsigned long) outbound_spi, (unsigned long) inbound_spi));

    return NULL;
}

/************** Management of outbound SPI's **********************/

bool
ssh_pm_spi_mark_neg_started(SshPm pm,
                            uint32_t outbound_spi,
                            uint32_t inbound_spi)
{
    SshPmSpiOut spi_out;

    spi_out = ssh_pm_lookup_outbound_spi_by_inbound_spi(pm, outbound_spi,
                                                        inbound_spi);
    if (spi_out == NULL)
      return false;

    SSH_DEBUG(SSH_D_MIDOK,
              ("Successfully marked SPI %08lx-%08lx as negotiation ongoing",
               (unsigned long) inbound_spi,
               (unsigned long) outbound_spi));

    spi_out->neg_in_progress = 1;
    return true;
}

bool
ssh_pm_spi_mark_neg_finished(SshPm pm,
                             uint32_t outbound_spi,
                             uint32_t inbound_spi)
{
    SshPmSpiOut spi_out;

    spi_out = ssh_pm_lookup_outbound_spi_by_inbound_spi(pm, outbound_spi,
                                                        inbound_spi);
    if (spi_out == NULL)
      return false;

    SSH_DEBUG(SSH_D_MIDOK,
              ("Successfully marked SPI %08lx-%08lx as negotiation finished",
               (unsigned long) inbound_spi,
               (unsigned long) outbound_spi));

    spi_out->neg_in_progress = 0;
    return true;
}

bool
ssh_pm_spi_neg_ongoing(SshPm pm,
                       uint32_t outbound_spi,
                       uint32_t inbound_spi)
{
    SshPmSpiOut spi_out;

    spi_out = ssh_pm_lookup_outbound_spi_by_inbound_spi(pm, outbound_spi,
                                                        inbound_spi);
    if (spi_out == NULL || spi_out->neg_in_progress == 0)
      return false;

    return true;
}
