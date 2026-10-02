
int natapi(char * buff, char* d_filename); // don't use , 
int natapi_init(struct natnl_config * nat_cfg, struct natnl_srv_port* pnat_srvports,char* n_callee, struct natnl_callback* pnatnl_callback);
int natapi_make_call(struct natnl_srv_port* nat_srvports );
int natapi_deinit();
int natapi_hangup_call();
int natapi_getfile(char* d_filename);
int natapi_putfile(char* d_filename);
int natapi_quit();
