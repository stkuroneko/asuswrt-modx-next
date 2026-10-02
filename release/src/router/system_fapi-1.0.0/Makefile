# ******************************************************************************** #
#       Copyright (c) 2015                                                         #
#       Lantiq Beteiligungs-GmbH & Co. KG                                          #
#       Lilienthalstrasse 15, 85579 Neubiberg, Germany                             #
#       For licensing information, see the file 'LICENSE' in the root folder of    #
#        this software module.                                                     #
# *******************************************************************************  #

PKG_NAME := system_fapi

bins := \
        libsysfapi.so \
        libethfapi.so


libsysfapi.so_sources := fapi_sys.c fapi_led.c fapi_processorstat.c fapi_interface.c  fapi_common.c\
		$(if $(PLATFORM_XRX200),xRX220/platform_xrx220.c) \
		$(if $(PLATFORM_XRX500),xRX350/platform_xrx350.c) \
		$(if $(PLATFORM_XRX750),xRX750/platform_xrx750.c)

libsysfapi.so_cflags := -I./include/ \
		$(if $(PLATFORM_XRX200),-I./xRX220/) \
		$(if $(PLATFORM_XRX500),-I./xRX350/) \
		$(if $(PLATFORM_XRX750),-I./xRX750/)

libsysfapi.so_ldflags := -L./ -lscapi

libethfapi.so_sources := fapi_eth.c switch_func.c switchFuncs_common.c \
		$(if $(PLATFORM_XRX200),xRX220/switchFuncs_xrx220.c) \
		$(if $(PLATFORM_XRX500),xRX350/switchFuncs_xrx350.c) \
		$(if $(PLATFORM_XRX750),xRX750/switchFuncs_xrx750.c)

libethfapi.so_cflags := -I./include/ \
		$(if $(PLATFORM_XRX200),-I./xRX220/) \
		$(if $(PLATFORM_XRX500),-I./xRX350/) \
		$(if $(PLATFORM_XRX750),-I./xRX750/)

libethfapi.so_ldflags := -L./ -lsysfapi -lscapi


include make.inc
