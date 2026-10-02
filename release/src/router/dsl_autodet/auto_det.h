enum {
	DSL_AUTODET_STATE_NONE = 0,
	DSL_AUTODET_STATE_DETECTING,
	DSL_AUTODET_STATE_DHCP,
	DSL_AUTODET_STATE_PPPOE,
	DSL_AUTODET_STATE_PPPOA,
	DSL_AUTODET_STATE_FAIL,
	DSL_AUTODET_STATE_NOLINK,
};

enum{
	DSL_AUTODET_WAN_TYPE_ATM = 0,
	DSL_AUTODET_WAN_TYPE_PTM,
};

enum {
	ATM_PROTO_PPPOE = 1,
	ATM_PROTO_PPPOA,
	ATM_PROTO_DHCP,
};

enum {
	ATM_ENCAP_LLC = 0,
	ATM_ENCAP_VC,
};

typedef struct {
	int vpi;
	int vci;
	int proto;
	int encap;
} atm_pvc_t;

typedef struct {
	int cap;
	int wans_cap;
	int wans_l2det;
	int wans_l3det;
} autodet_conf_t;

// config.c
void init_config(autodet_conf_t* config);
int is_dsl_plugged();
int is_dsl_link_up();
int is_vdsl();
void set_wan_type(int type);
void set_autodet_state(int state);
void set_autodet_state_eth(int state, int auxstate);
void set_atm_pvc_result(int vpi, int vci, int encap);
void get_eth_wan_interface(char *buf, size_t len);

// sysdeps api
extern int create_atm_intf(atm_pvc_t* pvc, char *iface, size_t if_len);
extern int delete_atm_intf(atm_pvc_t* pvc, const char *iface);
extern int is_eth_wan_link_up();
