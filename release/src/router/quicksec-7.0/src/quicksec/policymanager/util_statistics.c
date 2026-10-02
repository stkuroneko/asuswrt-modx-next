/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for retrieving statistics for the policy manager.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmStats"

/* Context data for the global statistics retrieving. */
struct SshPmGlobalStatsCtxRec
{
    SshPmGlobalStatsCB callback;
    void *context;
};

typedef struct SshPmGlobalStatsCtxRec SshPmGlobalStatsCtxStruct;
typedef struct SshPmGlobalStatsCtxRec *SshPmGlobalStatsCtx;


/************************** Static help functions ***************************/

/**************************** Global statistics *****************************/

void
ssh_pm_get_global_stats(SshPm pm, SshPmGlobalStatsCB callback, void *context)
{
    if (callback != NULL)
        (*callback)(pm, &pm->stats, context);
}

void
ssh_pm_get_ipsec_sa_stats(SshPm pm, SshPmIPsecSaStats ipsec_sa_stats)
{

    ipsec_sa_stats->created = pm->ipsec_sa_stats.created;
    ipsec_sa_stats->rekeyed = pm->ipsec_sa_stats.rekeyed;
    ipsec_sa_stats->deleted = pm->ipsec_sa_stats.deleted;
}

