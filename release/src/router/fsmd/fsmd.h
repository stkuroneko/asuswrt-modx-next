/*
 * Copyright © 2021 ASUSTeK COMPUTER INC. All rights reserved.
 */

#define FSMD_SOCKET_PATH "/var/run/fsmd_socket"

void initial_jffs_quota();
void destroy_jffs_quota();
void update_jffs_usage();
void check_jffs_quota();
void dump_jffs_usage(const char* path);

enum {
	FSM_S_DUMP = 0
};

typedef struct fsm_sock_data {
	int        d_type;             // Data type
	union {
	char dump_path[64];            // Dump file path
	};
} fsm_sock_data_t;
