#ifndef __CMD_HEADER_DLL_H__
#define __CMD_HEADER_DLL_H__

#define CMD_MAGIC 0x37658927

enum {CMD_GET_FILE = 100, CMD_PUT_FILE, CMD_SEND_TEST, CMD_GET_DATA, CMD_PUT_DATA};

struct cmd_header {
	int magic; //CMD_MAGIC 0x37658927
	int cmd;
	int data_size;
} cmd_header;

#endif	/* __CMD_HEADER_DLL_H__ */