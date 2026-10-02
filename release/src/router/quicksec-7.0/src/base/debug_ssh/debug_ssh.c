/**
   @copyright
   Copyright (c) 2011 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "implementation_defs.h"
#include "sshincludes.h"
#include "sshdebug.h"

#include <stdarg.h>
#include <string.h>
#include <stdio.h>

void
debug_outputf(
        const char *level,
        const char *flow,
        const char *module,
        const char *file,
        int line,
        const char *func,
        const char *format, ...)
{
    int ssh_level = 10;

    if (strcmp("FAIL", level) == 0)
    {
        ssh_level = SSH_D_FAIL;
    }
    else
    if (strcmp("HIGH", level) == 0)
    {
        ssh_level = SSH_D_HIGHOK;
    }
    else
    if (strcmp("MEDIUM", level) == 0)
    {
        ssh_level = SSH_D_MIDOK;
    }
    else
    if (strcmp("LOW", level) == 0)
    {
        ssh_level = SSH_D_LOWOK;
    }

    if ((SSH_DEBUG_COMPILE_TIME_MAX_LEVEL == 999999 ||
         ssh_level <= SSH_DEBUG_COMPILE_TIME_MAX_LEVEL) &&
        ssh_debug_enabled(module, ssh_level))
    {
        char message[1024];
        va_list args;

        va_start(args, format);
#undef vsnprintf
        vsnprintf(message, sizeof message, format, args);
        va_end(args);


        ssh_debug_output(
                ssh_level,
                file,
                line,
                module,
                func,
                ssh_debug_format("%s", message));
    }
}


extern void
assert_outputf(
        const char *condition,
        const char *file,
        int line,
        const char *module,
        const char *func,
        const char *description)
{
    ssh_generic_assert(condition, file, line, module, func, 2);
}
