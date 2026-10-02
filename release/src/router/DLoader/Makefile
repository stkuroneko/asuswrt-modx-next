#*************************************************************************
# Copyright (c) 2014, spreadtrum Corp., All rights reserved.
#
# File Name	: Makefile
#
# Purpose	: It will compile the listenerifc file and link all
#			  necessary libraries to create the final executable.
#
# Author	: xiongding@gmail.com
#
# Date		: 23  6   2014
#
#*************************************************************************

include ../common.mak
# ------------- Directory path for source files -------------
SYSTEM_SRC_DIR=./src
SYSTEM_HDR_DIR=./include

# ------------- Directory Path for header files -------------
MEMPOOL_SRC_DIR=./Mempool
MEMPOOL_HDR_DIR=./Mempool

# ------------- Directory Path for library files -------------

LIB_DIR=lib

# ------------- Directory Path for object files -------------

OBJ_DIR=./bin

# ------------- Directory Path for binary files -------------

BIN_DIR=./bin

# ------------- Include directories -------------------
INC= -I$(SYSTEM_HDR_DIR) -I$(MEMPOOL_SRC_DIR)

# ------------- Compiler to compile source files ------------
#COMPILER=arm-linux-gcc
CROSS_COMPILE=$(patsubst %-gcc,%-,$(KERNELCC))
COMPILER=$(CROSS_COMPILE)gcc
# ------------- Compiler options -------------
COMP_OPT= $(target) -c -g -Wall -fno-strict-aliasing -O -O2 -o $@
#COMP_OPT=-c -Wall -fno-strict-aliasing -O -O2 -o $@
#COMP_OPT=-c -Os -o $@
# ------------- System options -------------
SYSTEM_OPT=-DUNIX -D_FILE_OFFSET_BITS=64
# ----------- Linker name to create executable ---------
LINKER_NAME=$(CROSS_COMPILE)gcc
#LINKER_NAME=ld
# -------------- Linker Options -------------
#LINKER_OPT=-g -o $@
LINKER_OPT= $(target) -o $@
OTHER_INC= -pthread -lsys -lstdc++ -lrt -L$(TOP_PLATFORM)/nvram${BCMEX}${EX7} -lnvram -L$(TOP)/shared -lshared -lcrypt -ldl
# ----------- Library utility to create library ---------
LIB_NAME=$(CROSS_COMPILE)ar

# -------------- Library utility Options -------------
LIB_OPT=-cr

# ------------- Library file extension -------------
LIB_EXT=a
#LIB_EXT=

# ------------- Object file extension -------------
OBJ_EXT=o

# ------------- Command to delete file(s) -------------
DEL=rm -f

# ------------- Command to display file(s) -------------
DIR=ls

# ------------- Agent header files -------------
SYSTEM_HDRS= $(SYSTEM_HDR_DIR)/BinPack.h		\
		$(SYSTEM_HDR_DIR)/BMFile.h		\
		$(SYSTEM_HDR_DIR)/BootModeIntegOpr.h	\
		$(SYSTEM_HDR_DIR)/BootModeObj.h	\
		$(SYSTEM_HDR_DIR)/Calibration.h	\
		$(SYSTEM_HDR_DIR)/crc16.h		\
		$(SYSTEM_HDR_DIR)/ExePathHelper.h		\
		$(SYSTEM_HDR_DIR)/ISpLog.h	\
		$(SYSTEM_HDR_DIR)/OptionHelpper.h	\
		$(SYSTEM_HDR_DIR)/SpLog.h	\
		$(SYSTEM_HDR_DIR)/tinyxml.h		\
		$(SYSTEM_HDR_DIR)/typedef.h		\
		$(SYSTEM_HDR_DIR)/BMAFImp.h	\
		$(SYSTEM_HDR_DIR)/BMFileImpl.h	\
		$(SYSTEM_HDR_DIR)/BootModeitf.h	\
		$(SYSTEM_HDR_DIR)/BootModeOpr.h		\
		$(SYSTEM_HDR_DIR)/Calibration.h		\
		$(SYSTEM_HDR_DIR)/crc.h	\
		$(SYSTEM_HDR_DIR)/Global.h	\
		$(SYSTEM_HDR_DIR)/MasterImgGen.h	\
		$(SYSTEM_HDR_DIR)/ProcMonitor.h		\
		$(SYSTEM_HDR_DIR)/Test.h		\
		$(SYSTEM_HDR_DIR)/TTYComm.h	\
		$(SYSTEM_HDR_DIR)/XmlConfigParse.h	\
		$(SYSTEM_HDR_DIR)/BMAGlobal.h	\
		$(SYSTEM_HDR_DIR)/bmpacket.h		\
		$(SYSTEM_HDR_DIR)/BootModeObject.h	\
		$(SYSTEM_HDR_DIR)/BootParamDef.h	\
		$(SYSTEM_HDR_DIR)/confile.h		\
		$(SYSTEM_HDR_DIR)/DLoader.h	\
		$(SYSTEM_HDR_DIR)/ICommChannel.h	\
		$(SYSTEM_HDR_DIR)/MemoryMgr.h		\
		$(SYSTEM_HDR_DIR)/Settings.h	\
		$(SYSTEM_HDR_DIR)/tinystr.h	\
		$(SYSTEM_HDR_DIR)/TTYComm.h		\
		$(SYSTEM_HDR_DIR)/XMLite.h		\
		$(SYSTEM_HDR_DIR)/phdef.h		\
		$(SYSTEM_HDR_DIR)/PhaseCheckBuild.h		\
		$(SYSTEM_HDR_DIR)/XRandom.h		\
		$(MEMPOOL_SRC_DIR)/dlmalloc.h


# ------------- System object files -------------
SYSTEM_OBJS= $(OBJ_DIR)/XmlConfigParse.o \
		$(OBJ_DIR)/typedef.o \
		$(OBJ_DIR)/TTYComm2.o \
		$(OBJ_DIR)/TTYComm.o \
		$(OBJ_DIR)/tinyxmlparser.o \
		$(OBJ_DIR)/tinyxmlerror.o \
		$(OBJ_DIR)/tinyxml.o \
		$(OBJ_DIR)/tinystr.o \
		$(OBJ_DIR)/SpLog.o \
		$(OBJ_DIR)/Settings.o \
		$(OBJ_DIR)/ProcMonitor.o \
		$(OBJ_DIR)/OptionHelpper.o \
		$(OBJ_DIR)/MemoryMgr.o \
		$(OBJ_DIR)/MasterImgGen.o \
		$(OBJ_DIR)/DLoader.o \
		$(OBJ_DIR)/CTest.o \
		$(OBJ_DIR)/crc16.o \
		$(OBJ_DIR)/crc.o \
		$(OBJ_DIR)/confile.o \
		$(OBJ_DIR)/Calibration.o \
		$(OBJ_DIR)/BootModeOpr.o \
		$(OBJ_DIR)/BootModeObject.o \
		$(OBJ_DIR)/BootModeObj.o \
		$(OBJ_DIR)/BootModeIntegOpr.o \
		$(OBJ_DIR)/bmpacket.o \
		$(OBJ_DIR)/BMFileImpl.o \
		$(OBJ_DIR)/BMAFImp.o \
		$(OBJ_DIR)/BinPack.o \
		$(OBJ_DIR)/PhaseCheckBuild.o \
		$(OBJ_DIR)/XRandom.o	\
		$(OBJ_DIR)/dlmalloc.o

# -------------Compilation starts here-------------$(OBJ_DIR)/dlmalloc.o \
#all:$(SYSTEM_OBJS)
#	$(LIB_NAME) $(LIB_OPT) $(LIB_DIR)/libsys.$(LIB_EXT) $(SYSTEM_OBJS)

all: $(LIB_DIR)/libsys.$(LIB_EXT) main

$(LIB_DIR)/libsys.$(LIB_EXT): $(SYSTEM_OBJS) $(SYSTEM_HDRS)
	$(LIB_NAME) $(LIB_OPT) $(LIB_DIR)/libsys.$(LIB_EXT) $(SYSTEM_OBJS)

clean:
	$(DIR) $(OBJ_DIR)/*.$(OBJ_EXT)
	$(DIR) $(LIB_DIR)/*.$(LIB_EXT)
	$(DEL) $(OBJ_DIR)/*.$(OBJ_EXT)
	$(DEL) $(LIB_DIR)/*.$(LIB_EXT)
	$(DEL) main.o
	$(DEL) DLoader

# ------------- Compilation commands -------------

main.o: main.cpp 
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) ./main.cpp  

main: $(LIB_DIR)/libsys.$(LIB_EXT) main.o
	$(LINKER_NAME)  $(LINKER_OPT) main.o -Llib -L$(OBJ_DIR) -L$(SYSTEM_HDR_DIR) $(OTHER_INC)
#	sudo cp main	 ../Bin/sprd_dloader/DLoader
	cp main	 ./DLoader
#	sudo cp "../DLoader Release Notes.xls" ../publish/sprd_dloader
#	sudo cp -R ../Bin/. ../publish/sprd_dloader/Bin

# ............. System related files .............

$(OBJ_DIR)/XmlConfigParse.o: $(SYSTEM_SRC_DIR)/XmlConfigParse.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/XmlConfigParse.cpp

$(OBJ_DIR)/typedef.o: $(SYSTEM_SRC_DIR)/typedef.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/typedef.cpp

$(OBJ_DIR)/TTYComm.o: $(SYSTEM_SRC_DIR)/TTYComm.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/TTYComm.cpp

$(OBJ_DIR)/TTYComm2.o: $(SYSTEM_SRC_DIR)/TTYComm2.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/TTYComm2.cpp

$(OBJ_DIR)/tinyxmlparser.o: $(SYSTEM_SRC_DIR)/tinyxmlparser.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/tinyxmlparser.cpp

$(OBJ_DIR)/tinyxmlerror.o: $(SYSTEM_SRC_DIR)/tinyxmlerror.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/tinyxmlerror.cpp

$(OBJ_DIR)/tinyxml.o: $(SYSTEM_SRC_DIR)/tinyxml.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/tinyxml.cpp

$(OBJ_DIR)/tinystr.o: $(SYSTEM_SRC_DIR)/tinystr.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/tinystr.cpp

$(OBJ_DIR)/SpLog.o: $(SYSTEM_SRC_DIR)/SpLog.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/SpLog.cpp

$(OBJ_DIR)/Settings.o: $(SYSTEM_SRC_DIR)/Settings.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/Settings.cpp

$(OBJ_DIR)/ProcMonitor.o: $(SYSTEM_SRC_DIR)/ProcMonitor.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/ProcMonitor.cpp

$(OBJ_DIR)/OptionHelpper.o: $(SYSTEM_SRC_DIR)/OptionHelpper.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/OptionHelpper.cpp

$(OBJ_DIR)/MemoryMgr.o: $(SYSTEM_SRC_DIR)/MemoryMgr.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/MemoryMgr.cpp

$(OBJ_DIR)/MasterImgGen.o: $(SYSTEM_SRC_DIR)/MasterImgGen.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/MasterImgGen.cpp

$(OBJ_DIR)/DLoader.o: $(SYSTEM_SRC_DIR)/DLoader.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/DLoader.cpp

$(OBJ_DIR)/CTest.o: $(SYSTEM_SRC_DIR)/CTest.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/CTest.cpp

$(OBJ_DIR)/crc16.o: $(SYSTEM_SRC_DIR)/crc16.c $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/crc16.c

$(OBJ_DIR)/crc.o: $(SYSTEM_SRC_DIR)/crc.c $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/crc.c

$(OBJ_DIR)/confile.o: $(SYSTEM_SRC_DIR)/confile.c $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/confile.c

$(OBJ_DIR)/Calibration.o: $(SYSTEM_SRC_DIR)/Calibration.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/Calibration.cpp

$(OBJ_DIR)/BootModeOpr.o: $(SYSTEM_SRC_DIR)/BootModeOpr.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/BootModeOpr.cpp

$(OBJ_DIR)/BootModeObject.o: $(SYSTEM_SRC_DIR)/BootModeObject.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/BootModeObject.cpp

$(OBJ_DIR)/BootModeObj.o: $(SYSTEM_SRC_DIR)/BootModeObj.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/BootModeObj.cpp

$(OBJ_DIR)/BootModeIntegOpr.o: $(SYSTEM_SRC_DIR)/BootModeIntegOpr.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/BootModeIntegOpr.cpp

$(OBJ_DIR)/bmpacket.o: $(SYSTEM_SRC_DIR)/bmpacket.c $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/bmpacket.c

$(OBJ_DIR)/BMFileImpl.o: $(SYSTEM_SRC_DIR)/BMFileImpl.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/BMFileImpl.cpp

$(OBJ_DIR)/BMAFImp.o: $(SYSTEM_SRC_DIR)/BMAFImp.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/BMAFImp.cpp

$(OBJ_DIR)/BinPack.o: $(SYSTEM_SRC_DIR)/BinPack.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/BinPack.cpp

$(OBJ_DIR)/PhaseCheckBuild.o: $(SYSTEM_SRC_DIR)/PhaseCheckBuild.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/PhaseCheckBuild.cpp

$(OBJ_DIR)/XRandom.o: $(SYSTEM_SRC_DIR)/XRandom.cpp $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(SYSTEM_SRC_DIR)/XRandom.cpp

$(OBJ_DIR)/dlmalloc.o: $(MEMPOOL_SRC_DIR)/dlmalloc.c $(SYSTEM_HDRS)
	$(COMPILER) $(COMP_OPT) $(SYSTEM_OPT) $(INC) $(MEMPOOL_SRC_DIR)/dlmalloc.c




install: all
	install -D DLoader $(INSTALLDIR)/bin/DLoader
	$(STRIP) $(INSTALLDIR)/bin/DLoader
	chmod 0500 $(INSTALLDIR)/bin/DLoader


#*************************************************************************
#					 End of Makefile
#*************************************************************************
