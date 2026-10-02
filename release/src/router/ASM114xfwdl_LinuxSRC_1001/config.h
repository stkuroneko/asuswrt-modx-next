/*
 * Definitions of Asmedia ASM2114 Firmware Configure Table Access Functions
 *
 * Copyright (C) 2015-2018 ASMedia Technology
 */

#ifndef	_CONFIG_H_
#define	_CONFIG_H_

enum cfg_state
{
    CFG_GET_SECSSION = 0,
    CFG_GET_MEMBER,
};

typedef struct _cfg_item
{
    char *name;
    BYTE head;
    BYTE type;
    WORD address;
    DWORD value;
    BYTE modified:1;
    BYTE reserved:7;
} cfg_item;

typedef struct _str_item
{
    char *name;
    DWORD value;
    BYTE modified:1;
    BYTE reserved:7;
} str_item;

#define MAX_LINE_SIZE   256

#endif  /* _CONFIG_H_ */

