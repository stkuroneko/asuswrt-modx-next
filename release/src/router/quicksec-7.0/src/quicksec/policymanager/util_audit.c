/**
   @copyright
   Copyright (c) 2003 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager audit callback storing the events into ring buffer
   and optionally sending them into syslog or file.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshaudit.h"
#include "sshaudit_syslog.h"
#include "sshaudit_file.h"

#define SSH_DEBUG_MODULE "SshPmAudit"

#if SSH_PM_AUDIT_REQUESTS_PER_SECOND == 0
#define SSH_PM_AUDIT_MIN_REQUEST_INTERVAL 0
#else
#define SSH_PM_AUDIT_MIN_REQUEST_INTERVAL \
        (1000000 / SSH_PM_AUDIT_REQUESTS_PER_SECOND)
#endif


/************************************************************************/

/* Forward declarations */
static void ssh_pm_remove_audit_module(SshPm pm, uint32_t audit_id);

void
ssh_pm_audit_event(SshPm pm, uint32_t audit_subsystem,
                   SshAuditEvent event, ...)
{
    SshPmAuditModule module;
    va_list ap;

    module = pm->audit.modules;
    while (module)
    {
        if (module->audit_subsystems & audit_subsystem)
        {
            va_start(ap, event);
            ssh_audit_event_va(module->context, event, ap);
            va_end(ap);
        }
        module = module->next;
    }
}

static void ike_audit_callback(SshAuditEvent event, uint32_t argc,
                               SshAuditArgument argv, void *context)
{
    SshPm pm = context;
    SshPmAuditModule module;

    module = pm->audit.modules;
    while (module)
    {
        if (module->audit_subsystems & SSH_PM_AUDIT_IKE)
        {
            ssh_audit_event_array(module->context, event, argc, argv);
        }
        module = module->next;
    }
}

/* Initialize the policy manager's audit framework. */
bool ssh_pm_audit_init(SshPm pm)
{
    SSH_DEBUG(SSH_D_LOWOK, ("Initializing the PM audit module"));

    pm->audit.ike_audit = ssh_audit_create(ike_audit_callback, NULL_FNPTR, pm);

    if (pm->audit.ike_audit == NULL)
      return false;

    pm->audit.request_interval = SSH_PM_AUDIT_MIN_REQUEST_INTERVAL;

    pm->audit.last_resource_failure_time = ssh_time();
    pm->audit.last_flood_time = ssh_time();

    return true;
}

/* Uninitialize the audit modules from the policy manager `pm'. */
void ssh_pm_audit_uninit(SshPm pm)
{
    SshPmAuditModule module = pm->audit.modules, next_module;

    SSH_DEBUG(SSH_D_LOWOK, ("Uninitializing the PM audit modules"));

    /* Remove all configured audit modules */
    while (module)
    {
        next_module = module->next;
        ssh_pm_remove_audit_module(pm, module->audit_id);
        module = next_module;
    }

    SSH_ASSERT(pm->audit.modules == NULL);

    ssh_audit_destroy(pm->audit.ike_audit);

    /* Cancel timeouts. */
    ssh_cancel_timeout(&pm->audit.timer);
    ssh_cancel_timeout(&pm->audit.retry_timer);
}

void ssh_pm_audit_syslog_destroy(void *context)
{
    SshAuditSyslogContext syslog = context;

    ssh_audit_syslog_destroy(syslog);
}

void ssh_pm_audit_file_destroy(void *context)
{
    SshAuditFileContext file = context;

    ssh_audit_file_destroy(file);
}


SshAuditContext ssh_pm_create_audit_module(SshPm pm,
                                           SshAuditFormatType format,
                                           const char *audit_name)
{
    SshAuditSyslogContext audit_syslog_context;
    SshAuditFileContext audit_file_context;
    SshAuditContext audit;
    bool append_newline = false;
    char *filename;

    SSH_DEBUG(SSH_D_HIGHOK, ("Creating audit module with name %s, and "
                             "format (%d)", audit_name, format));

    if (audit_name == NULL || !strcmp(audit_name, "syslog"))
    {
        if (format != SSH_AUDIT_FORMAT_DEFAULT)
        {
            SSH_DEBUG(SSH_D_FAIL, ("Invalid format type for syslog auditing"));

            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                          "Cannot use binary formatting for syslog "
                          "auditing.");
            return NULL;
        }

        audit_syslog_context = ssh_audit_syslog_create(SSH_LOGFACILITY_DAEMON,
                                                       SSH_LOG_INFORMATIONAL,
                                                       format);

        if (audit_syslog_context == NULL)
          return NULL;

        audit = ssh_audit_create(ssh_audit_syslog_cb,
                                 ssh_pm_audit_syslog_destroy,
                                 audit_syslog_context);
        if (audit == NULL)
          ssh_audit_syslog_destroy(audit_syslog_context);
        return audit;
    }
    else
    {
        filename = ssh_strdup(audit_name);

        if (filename == NULL)
          goto error;

        /* Only append newlines to non-binary (text) output formatters. */
        if (format == SSH_AUDIT_FORMAT_DEFAULT)
          append_newline = true;

        SSH_DEBUG(SSH_D_HIGHOK, ("Creating audit file %s", filename));

        audit_file_context = ssh_audit_file_create(filename,
                                                   append_newline,
                                                   format);
        ssh_free(filename);

        if (audit_file_context == NULL)
        {
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                          "Cannot create audit file context. Is '%s' a "
                          "valid file name?", audit_name);
            return NULL;
        }
        audit = ssh_audit_create(ssh_audit_file_cb,
                                 ssh_pm_audit_file_destroy,
                                 audit_file_context);

        return audit;
    }

   error:

    SSH_DEBUG(SSH_D_FAIL, ("Audit module creatiion failed (%s)", audit_name));
    ssh_free(filename);
    return NULL;
}

bool ssh_pm_attach_audit_module(SshPm pm,
                                   uint32_t audit_subsystems,
                                   SshAuditContext audit)
{
    SshPmAuditModule module;

    SSH_DEBUG(SSH_D_MIDOK, ("Attaching audit module"));

    module = ssh_calloc(1, sizeof(*module));
    if (module == NULL)
    {
        ssh_audit_destroy(audit);
        return false;
    }

    module->audit_subsystems = audit_subsystems;
    module->context = audit;
    module->audit_id = pm->next_audit_id++;

    /* Link the module to the policy managers list of audit modules. */
    module->next = pm->audit.modules;
    pm->audit.modules = module;

    return true;
}

static void ssh_pm_remove_audit_module(SshPm pm, uint32_t audit_id)
{
    SshPmAuditModule *module_ptr, module;

    SSH_DEBUG(SSH_D_MIDOK, ("Removing audit module with id %d",
                            (int) audit_id));

    module_ptr = &pm->audit.modules;
    for (module = pm->audit.modules; module; module = module->next)
    {
        if (module->audit_id == audit_id)
          break;

        module_ptr = &module->next;
    }

    if (module)
    {
        SSH_DEBUG(SSH_D_MIDOK, ("Destroying audit module"));

        *module_ptr = module->next;

        ssh_audit_destroy(module->context);
        ssh_free(module);
    }
    else
    {
        SSH_DEBUG(SSH_D_FAIL, ("No configured audit module with this audit "
                               "id (%d)", (int) audit_id));
    }
}


