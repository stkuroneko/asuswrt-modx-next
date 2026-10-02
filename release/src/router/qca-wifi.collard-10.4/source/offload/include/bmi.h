/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */


//==============================================================================
// BMI declarations and prototypes
//
// Author(s): ="Atheros"
//==============================================================================
#ifndef _BMI_H_
#define _BMI_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Header files */
#include "athdefs.h"
#include "a_types.h"
#include "hif.h"
#include "a_osapi.h"
#include "bmi_msg.h"
#include "ol_if_athvar.h"
    

void
BMIInit(struct ol_ath_softc_net80211 *scn);

void
BMICleanup(struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIDone(HIF_DEVICE *device, struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIGetTargetInfo(HIF_DEVICE *device, struct bmi_target_info *targ_info, struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIReadMemory(HIF_DEVICE *device,
              A_UINT32 address,
              A_UCHAR *buffer,
              A_UINT32 length,
              struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIWriteMemory(HIF_DEVICE *device,
               A_UINT32 address,
               A_UCHAR *buffer,
               A_UINT32 length,
               struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIExecute(HIF_DEVICE *device,
           A_UINT32 address,
           A_UINT32 *param,
           struct ol_ath_softc_net80211 *scn);

A_STATUS
BMISetAppStart(HIF_DEVICE *device,
               A_UINT32 address,
               struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIReadSOCRegister(HIF_DEVICE *device,
                   A_UINT32 address,
                   A_UINT32 *param,
                   struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIWriteSOCRegister(HIF_DEVICE *device,
                    A_UINT32 address,
                    A_UINT32 param,
                    struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIrompatchInstall(HIF_DEVICE *device,
                   A_UINT32 ROM_addr,
                   A_UINT32 RAM_addr,
                   A_UINT32 nbytes,
                   A_UINT32 do_activate,
                   A_UINT32 *patch_id,
                   struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIrompatchUninstall(HIF_DEVICE *device,
                     A_UINT32 rompatch_id,
                     struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIrompatchActivate(HIF_DEVICE *device,
                    A_UINT32 rompatch_count,
                    A_UINT32 *rompatch_list,
                    struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIrompatchDeactivate(HIF_DEVICE *device,
                      A_UINT32 rompatch_count,
                      A_UINT32 *rompatch_list,
                      struct ol_ath_softc_net80211 *scn);

A_STATUS 
BMISignStreamStart(HIF_DEVICE *device,
                   A_UINT32 address,
                   A_UCHAR *buffer,
                   A_UINT32 length,
                   struct ol_ath_softc_net80211 *scn);

A_STATUS
BMILZStreamStart(HIF_DEVICE *device,
                 A_UINT32 address,
                 struct ol_ath_softc_net80211 *scn);

A_STATUS
BMILZData(HIF_DEVICE *device,
          A_UCHAR *buffer,
          A_UINT32 length,
          struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIFastDownload(HIF_DEVICE *device,
                A_UINT32 address,
                A_UCHAR *buffer,
                A_UINT32 length,
                struct ol_ath_softc_net80211 *scn);

A_STATUS
BMInvramProcess(HIF_DEVICE *device,
                A_UCHAR *seg_name,
                A_UINT32 *retval,
                struct ol_ath_softc_net80211 *scn);

A_STATUS
BMIRawWrite(HIF_DEVICE *device,
            A_UCHAR *buffer,
            A_UINT32 length);

A_STATUS
BMIRawRead(HIF_DEVICE *device,
           A_UCHAR *buffer,
           A_UINT32 length,
           A_BOOL want_timeout);

#ifdef __cplusplus
}
#endif

#endif /* _BMI_H_ */
