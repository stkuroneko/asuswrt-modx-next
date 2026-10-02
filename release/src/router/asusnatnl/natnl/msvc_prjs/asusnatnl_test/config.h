#ifndef __CONFIG_DLL_H__
#define __CONFIG_DLL_H__

#include <getopt.h>
#include <natnl_lib.h>

#ifdef  __cplusplus
extern "C" {
#endif

extern char callee[128],
	registrar_uri[128];

#define DEV_ID1 "80bd8155a2540ef1e87ea2f811390e5d"
#define DEV_ID2 "ab8806d6e27ea16cd8c4557f8cb3179c"
#define SIP_SERVER "ec2-50-17-15-111.compute-1.amazonaws.com"
#define STUN_SERVER "stun.xten.com"
#define TURN_SERVER "numb.viagenie.ca"
#define TURN_USR "dean_li@asus.com"
#define TURN_PWD "asus"

extern int my_read_config_file(const char *filename, 
			    int *app_argc, char ***app_argv);
extern int my_parse_args(int argc, char *argv[],
					struct natnl_config *natnl_cfg,
					int *tnl_port_count,
					natnl_tnl_port tnl_port_cfg[],
					int *im_port_count,
					natnl_im_port im_port_cfg[]);

#ifdef  __cplusplus
}
#endif

#endif 	/* __CONFIG_DLL_H__ */
