#include "rc.h"

void stop_uu(void)
{
    killall_tk("uu-bootstrap.sh");
    killall_tk("uuplugin_monitor.sh");
    killall_tk("uuplugin");
}

void exec_uu(void)
{
    pid_t pid;
    char *argv[] = { "/usr/sbin/uu-bootstrap.sh", NULL };
    if (!nvram_match("uu_enable", "1") || !nvram_match("sw_mode", "1"))
        return;
    if (pidof("uu-bootstrap.sh") > 0 || pidof("uuplugin_monitor.sh") > 0)
        return;
    modprobe("tun");
    _eval(argv, NULL, 0, &pid);
}

void start_uu(void)
{
    if (getpid() != 1) {
        notify_rc("start_uu");
        return;
    }
    stop_uu();
    exec_uu();
}
