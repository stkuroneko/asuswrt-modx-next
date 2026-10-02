/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  Google Inc.
 */

#include "bleencrypt.h"

#if defined(MAPAC1750)
#define UUID_AMAP     0xAB01
#elif defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAX56_XD4) || defined(XD4PRO)
#define UUID_AMAP     0xAB85
#elif defined(RTAXE95Q) || defined(ET8PRO)
#define UUID_AMAP     0xAB8A
#else
#define UUID_AMAP     0xAB00
#endif
#define GATT_CHARAC_AMAP_PRODUCT                      0xAB10

#define MAX_AMAP_SERVICE	4

void amap_gatt_service(struct btd_adapter *adapter);
