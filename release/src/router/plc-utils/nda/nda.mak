# file: nda/nda.mak

# ====================================================================
# programs;
# --------------------------------------------------------------------

adccap3.o: adccap3.c error.h flags.h getoptv.h mme.h number.h plc.h putoptv.h symbol.h
ampinit.o: ampinit.c HPAVKey.h error.h files.h flags.h getoptv.h keys.h memory.h nda.h number.h nvm.h pib.h plc.h putoptv.h sdram.h symbol.h types.h
ampinit2.o: ampinit2.c HPAVKey.h error.h files.h flags.h getoptv.h keys.h memory.h nda.h number.h nvm.h pib.h plc.h putoptv.h sdram.h symbol.h types.h
arpc.o: arpc.c getoptv.h putoptv.h memory.h types.h flags.h files.h error.h channel.h 
int6kecho.o: int6kecho.c error.h files.h flags.h getoptv.h memory.h mme.h nda.h number.h plc.h putoptv.h symbol.h types.h
int6kp.o: int6kp.c HPAVKey.h error.h files.h flags.h getoptv.h keys.h memory.h nda.h number.h nvm.h pib.h plc.h putoptv.h sdram.h symbol.h types.h
int6kprobe.o: int6kprobe.c error.h files.h flags.h getoptv.h memory.h nda.h number.h plc.h putoptv.h symbol.h types.h
plcecho.o: plcecho.c error.h files.h flags.h getoptv.h memory.h mme.h nda.h number.h plc.h putoptv.h symbol.h types.h
plcinit.o: plcinit.c HPAVKey.h channel.h error.h files.h flags.h getoptv.h keys.h memory.h nda.h number.h nvm.h pib.h plc.h putoptv.h sdram.h symbol.h types.h
plcmcinfo.o: plcmcinfo.c HPAVKey.h channel.h error.h files.h flags.h getoptv.h keys.h memory.h number.h nvm.h pib.h plc.h putoptv.h sdram.h symbol.h types.h
plcmod.o: plcmod.c channel.h error.h files.h flags.h getoptv.h keys.h memory.h nda.h number.h plc.h putoptv.h symbol.h types.h
plcsnif.o: plcsnif.c error.h files.h flags.h getoptv.h memory.h nda.h number.h plc.h putoptv.h symbol.h types.h
psdump.o: psdump.c chars.h error.h getoptv.h number.h pib.h plc.h types.h

# ====================================================================
# functions;
# --------------------------------------------------------------------

AccessLevel.o: AccessLevel.c error.h plc.h
AccessLevelPTS.o: AccessLevelPTS.c error.h nda.h plc.h
EraseFlashMemory.o: EraseFlashMemory.c nda.h plc.h
EraseFlashMemory1.o: EraseFlashMemory1.c error.h flags.h memory.h plc.h
EraseFlashMemory2.o: EraseFlashMemory2.c error.h memory.h nda.h nvram.h plc.h symbol.h
EraseFlashSector.o: EraseFlashSector.c error.h memory.h nda.h plc.h
FlashPTS.o: FlashPTS.c error.h flags.h memory.h plc.h
Loopback.o: Loopback.c error.h memory.h plc.h
ModuleErase.o: ModuleErase.c error.h plc.h
Monitor.o: Monitor.c nda.h plc.h
MulticastInfo1.o: MulticastInfo1.c error.h memory.h number.h plc.h
MulticastInfo2.o: MulticastInfo2.c error.h memory.h number.h plc.h
NetworkProbe.o: NetworkProbe.c error.h memory.h number.h plc.h
psgen.o: psgen.c error.h flags.h getoptv.h psgen.h putoptv.h symbol.h types.h version.h
psgen_util.o: psgen_util.c error.h files.h pib.h psgen.h
RandomAddress.o: RandomAddress.c error.h mme.h nda.h plc.h
ReadFirmware3.o: ReadFirmware3.c nda.h plc.h 
ReadFlashFirmware.o: ReadFlashFirmware.c error.h files.h nda.h nvm.h plc.h
ReadFlashMemory.o: ReadFlashMemory.c nda.h plc.h
ReadFlashMemory1.o: ReadFlashMemory1.c endian.h error.h files.h memory.h nda.h plc.h
ReadFlashMemory2.o: ReadFlashMemory2.c endian.h error.h files.h memory.h nda.h nvram.h plc.h symbol.h
ReadFlashParameters.o: ReadFlashParameters.c error.h files.h nda.h pib.h plc.h
ReadParameters3.o: ReadParameters3.c nda.h plc.h 
Sniffer.o: Sniffer.c channel.h error.h flags.h memory.h mme.h plc.h

# ====================================================================
# headers;
# --------------------------------------------------------------------

nda.h: plc.h
psgen.h: files.h

