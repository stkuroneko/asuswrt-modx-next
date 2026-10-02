#include <natapi.h>
#include <stdio.h>
#include <log.h>

#define NATAPI_DBG 1
int lib_get_func(void* handle, const char* func_name, void** func_sym);

// global variable declare
void* lib_handle;

int lib_unload(void* handle)
{
	return dlclose(handle);
}

int lib_load(void** handle, const char* lib_path)
{
	*handle = NULL;
	*handle = dlopen(lib_path, RTLD_LAZY);
	if(!*handle){
		Cdbg(NATAPI_DBG, "dll get functions error =%s", dlerror());
		return -1;	
	}
	else
		return 0;
}

int lib_get_func(void* handle, const char* func_name, void** func_sym)
{
	if(!handle) return -1;
	*func_sym = dlsym(handle, func_name);
	if(!*func_sym) {
		Cdbg(NATAPI_DBG, "dll get functions error =%s", dlerror());
		return -1;
	}
	return 0;
}

int deinit_natnl_api()
{
	return 	lib_unload(lib_handle);
}

int init_natnl_api(NAT_INIT3* nat_init3, 
    NAT_DEINIT* nat_deinit, 
    NAT_MAKECALL* nat_makecall, 
    NAT_HANG_UP* nat_hangup, 
    NAT_POOL_DUMP* nat_dump , 
    NAT_DETECT* nat_detect, 
    NAT_VERSION* nat_version, 
    NAT_READ_IM_MSG* nat_read_im_msg, 
    NAT_WRITE_IM_RESP* nat_write_im_resp, 
    NAT_REG_DEVICE* nat_reg_device, 
    NAT_UNREG_DEVICE* nat_unreg_device, 
    NAT_MAKECALL3* nat_makecall3,
    NAT_READ_TNL_INFO *nat_read_ntl_info)
{
	int err = 0;
	char* error;

	err = lib_load(&lib_handle, "libasusnatnl.so");
	error = dlerror();

	Cdbg(NATAPI_DBG, "dlopen handle =%p\n", lib_handle);
	if (!lib_handle) {
		if (error != NULL)
			fprintf(stderr, "%s\n", error);
	} else {
		if (nat_init3) {
			*nat_init3	=   (NAT_INIT3)		dlsym(lib_handle, "natnl_lib_init3");
			if (!(*nat_init3))
				err = -2;
		}
		if (nat_deinit) {
			*nat_deinit	=   (NAT_DEINIT)	dlsym(lib_handle, "natnl_lib_deinit");
			if (!(*nat_deinit))
				err = -3;
		}
		if (nat_makecall) {
			*nat_makecall	=   (NAT_MAKECALL)	dlsym(lib_handle, "natnl_make_call");
			if (!(*nat_makecall))
				err = -4;
		}
		if (nat_hangup) {
			*nat_hangup	=   (NAT_HANG_UP)	dlsym(lib_handle, "natnl_hangup_call");
			if (!(*nat_hangup))
				err = -5;
		}
		if (nat_dump) {
			*nat_dump	=   (NAT_POOL_DUMP)	dlsym(lib_handle, "natnl_pool_dump");
			if (!(*nat_dump))
				err = -6;
		}
		if (nat_detect) {
			*nat_detect 	=   (NAT_DETECT)	dlsym(lib_handle, "natnl_detect_nat_type");
			if (!(*nat_detect))
				err = -7;
		}
		if (nat_version) {
			*nat_version	=   (NAT_VERSION)	dlsym(lib_handle, "natnl_lib_version");
			if (!(*nat_version))
				err = -8;
		}
		if (nat_read_im_msg) {
			*nat_read_im_msg    =   (NAT_READ_IM_MSG)    dlsym(lib_handle, "read_im_msg_from_shm");
			if (!(*nat_read_im_msg))
				err = -9;
		}
		if (nat_write_im_resp) {
			*nat_write_im_resp    =   (NAT_WRITE_IM_RESP)    dlsym(lib_handle, "write_im_resp_to_shm");
			if (!(*nat_write_im_resp))
				err = -10;
		}
		if (nat_unreg_device) {
			*nat_unreg_device    =   (NAT_UNREG_DEVICE)    dlsym(lib_handle, "natnl_unreg_device");
			if (!(*nat_unreg_device))
				err = -11;
		}
		if (nat_reg_device) {
			*nat_reg_device    =   (NAT_REG_DEVICE)    dlsym(lib_handle, "natnl_reg_device");
			if (!(*nat_reg_device))
				err = -12;
		}
		if (nat_makecall3) {
			*nat_makecall3	=   (NAT_MAKECALL)	dlsym(lib_handle, "natnl_make_call_with_inst_id2");
			if (!(*nat_makecall3))
				err = -13;
		}
		if (nat_read_ntl_info) {
			*nat_read_ntl_info	=   (NAT_MAKECALL)	dlsym(lib_handle, "natnl_read_tnl_info");
			if (!(*nat_read_ntl_info))
				err = -14;
		}
		Cdbg(NATAPI_DBG, "nat_init3 =%p\n, nat_deinit=%p\n, nat_makecall=%p\n, nat_hangup=%p\n, nat_dump=%p\n, nat_detect=%p\n, "
			"nat_version=%p\n, nat_read_im_msg=%p\n, nat_write_im_resp=%p\n, nat_reg_device=%p\n, nat_unreg_device=%p\n, nat_makecall3=%p\n, nat_read_ntl_info=%p\n", 
				nat_init3 ? *nat_init3 : NULL,
				nat_deinit? *nat_deinit : NULL,
				nat_makecall ? *nat_makecall : NULL,
				nat_hangup ? *nat_hangup : NULL,
				nat_dump ? *nat_dump : NULL,
				nat_detect ? *nat_detect : NULL,
				nat_version ? *nat_version : NULL,
				nat_read_im_msg ? *nat_read_im_msg : NULL,
				nat_write_im_resp ? *nat_write_im_resp : NULL,
				nat_reg_device ? *nat_reg_device : NULL,
				nat_unreg_device ? *nat_unreg_device : NULL,
				nat_makecall3 ? *nat_makecall3 : NULL,
				nat_read_ntl_info ? *nat_read_ntl_info : NULL);
		if (error != NULL) {
			fprintf(stderr, "%s\n", error);
			err = -1;
		}
	}

	return err;
}
