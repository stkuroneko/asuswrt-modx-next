#ifndef _VERSION_H
#define _VERSION_H

#ifndef TUNNEL_V
#define TUNNEL_V "2.1.0.128"
#endif

#define NATNL_LIB_VERSION TUNNEL_V 
#define NATNL_EXE_VERSION TUNNEL_V
#define NATNL_PRI	"tunnel version is "
#define NATNL_VERSION NATNL_PRI NATNL_LIB_VERSION
//PJ_DEF_DATA(const char*) NATNL_VERSION = NATNL_LIB_VERSION;

/*
 * Get PJLIB version string.
 */

const char* natnl_get_version(void);



#endif
