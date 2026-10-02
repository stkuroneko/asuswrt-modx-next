typedef struct {
	unsigned long duration;
	char log_path[128];
	int tillretrain;
} DIAG_PARAM;

void start_diag(DIAG_PARAM *p);
void stop_diag(DIAG_PARAM *p);
void dump_diag_log(DIAG_PARAM *p);
void dsl_downup();
void update_dsl_diag_state(int s);
int is_dsl_link_up();
