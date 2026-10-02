/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Event logging functions for Windows CE.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "event_log.h"

#ifdef _WIN32_WCE 

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshInterceptorEventLog"


/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

/*------------------------------------------------------------------------
  ssh_event_log_cb()
  
  Callback routine for posting messages into Windows event log.
  
  Arguments:
  facility - major function code
  severity - error code
  msg - log message 
  context - driver object
  
  Returns:
  Notes:
  ------------------------------------------------------------------------*/

static VOID
ssh_event_log_cb(SshLogFacility facility,
                 SshLogSeverity severity,
                 const char *msg,
                 PDRIVER_OBJECT driver)
{



}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

void
ssh_event_log_activate(PDRIVER_OBJECT driver)
{
  ssh_log_register_callback(ssh_event_log_cb, driver);
}

#endif /* _WIN32_WCE */

