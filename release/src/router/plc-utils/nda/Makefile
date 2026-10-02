#!/usr/bin/make -f
# file: nda/Makefile

# ====================================================================
# environment definitions;
# --------------------------------------------------------------------

include ../make.def

# ====================================================================
# symbols;
# --------------------------------------------------------------------

CFLAGS+=
LDFLAGS+=-lm
TRASH=*.o *.obj *.exe t t.* *~ *.[0-9][0-9][0-9] 
FILES=Makefile *.mak *.sh *.c *.h 
TOOLS=adccap3 arpc ampinit ampinit2 plcecho plcinit plcmcinfo plcmod plcsnif psgen psdump int6kbootp int6kecho int6kfp int6kp int6kprobe
PAGES=adccap3.1 arpc.1 ampinit.1 ampinit2.1 plcecho.1 plcinit.1 plcmcinfo.1 plcmod.1 plcsnif.1 psgen.1 int6kbootp.1 int6kecho.1 int6kfp.1 int6kp.1 int6kprobe.1 

# ====================================================================
# pseudo targets;
# --------------------------------------------------------------------

all compile: ${TOOLS}
compact: compile
	if [ ! -z ${STRIP} ]; then ${STRIP} ${TOOLS}; fi
	if [ -x /usr/local/bin/upx ]; then upx --best ${TOOLS}; fi
library:
ifeq ($(PLC_UTILS),y)
	install -d ${BIN}
else
	install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${BIN}
endif
scripts:
manuals:
	if [ ! -d ${MAN} ]; then install -m ${DIR_PERM} -o ${OWNER} -g ${GROUP} -d ${MAN}; fi
	install -m ${MAN_PERM} -o ${OWNER} -g ${GROUP} ${PAGES} ${MAN}
install: compile library
ifeq ($(PLC_UTILS),y)
	install ${TOOLS} ${BIN}
else
	install -m ${SUID_PERM} -o ${OWNER} -g ${GROUP} ${TOOLS} ${BIN}
endif
uninstall:
	cd ${BIN}; rm -f plc ${TOOLS}
	cd ${MAN}; rm -f plc ${PAGES}
clean:
	rm -f ${TRASH} ${TOOLS}
check:
	${SHELL} nda.sh
ignore:
	echo ${TOOLS} | tr ' ' '\n' > .gitignore

# ====================================================================
# rules;        
# --------------------------------------------------------------------

%: %.o
	${CC} -o ${@} ${^} ${LDFLAGS}
%.o: %.c
	${CC} -c ${<} ${CFLAGS}

# ====================================================================
# programs;     
# --------------------------------------------------------------------

adccap3: adccap3.o Devices.o EthernetHeader.o Failure.o MMECode.o QualcommHeader1.o ReadFMI.o ReadMME.o SendMME.o UnwantedMessage.o channel.o checkfilename.o closechannel.o error.o getoptv.o hexdecode.o hexdump.o hexencode.o hexstring.o openchannel.o putoptv.o readpacket.o sendpacket.o synonym.o todigit.o uintspec.o version.o
ampinit: ampinit.o Attributes1.o Confirm.o Devices.o Display.o EraseFlashMemory1.o EthernetHeader.o FactoryDefaults.o Failure.o FlashDevice3.o FlashPTS.o QualcommHeader1.o HostActionResponse.o Identity1.o MMECode.o NVRAMInfo.o NetInfo2.o PushButton.o QualcommHeader.o ReadFirmware1.o ReadFlashFirmware.o ReadFlashParameters.o ReadMFG.o ReadMME.o ReadParameters1.o RemoteHosts.o Request.o ResetDevice.o SDRAMInfo.o SendMME.o SetNMK.o StationRole.o UnwantedMessage.o VersionInfo1.o WaitForReset.o WaitForRestart.o WaitForStart.o WatchdogReport.o WriteCFG.o WriteNVM.o WritePIB.o basespec.o channel.o checkfilename.o checksum32.o chipset.o closechannel.o error.o fdchecksum32.o getoptv.o hexdecode.o hexdump.o hexencode.o hexout.o hexstring.o keys.o lightning_nvm_file.o nvram.o openchannel.o lightning_pib_file.o lightning_pib_peek.o putoptv.o readpacket.o sdramfile.o sdrampeek.o sendpacket.o strfbits.o synonym.o todigit.o typename.o uintspec.o version.o
ampinit2: ampinit2.o Attributes1.o Confirm.o Devices.o Display.o EraseFlashMemory2.o EthernetHeader.o FactoryDefaults.o Failure.o FlashDevice2.o FlashPTS.o QualcommHeader1.o HostActionResponse.o Identity1.o MMECode.o NVRAMInfo.o NetInfo2.o PushButton.o QualcommHeader.o ReadFirmware1.o ReadFlashFirmware.o ReadFlashParameters.o ReadMFG.o ReadMME.o ReadParameters1.o RemoteHosts.o Request.o ResetDevice.o SDRAMInfo.o SendMME.o SetNMK.o StationRole.o UnwantedMessage.o VersionInfo1.o WaitForReset.o WaitForRestart.o WaitForStart.o WatchdogReport.o WriteCFG.o basespec.o channel.o checkfilename.o checksum32.o chipset.o closechannel.o error.o fdchecksum32.o getoptv.o hexdecode.o hexdump.o hexencode.o hexout.o hexstring.o keys.o lightning_nvm_file.o nvram.o openchannel.o lightning_pib_file.o lightning_pib_peek.o putoptv.o readpacket.o sdramfile.o sdrampeek.o sendpacket.o strfbits.o synonym.o todigit.o typename.o uintspec.o version.o ModuleSpec.o ModuleSession.o ModuleRead.o ModuleWrite.o ModuleErase.o ModuleCommit.o FlashSoftloader.o FlashFirmware.o FlashParameters.o AccessLevelPTS.o ReadFlashMemory2.o
arpc: arpc.o ARPCPeek.o ARPCPrint.o ARPCWrite.o channel.o closechannel.o error.o getoptv.o hexdump.o hexwrite.o openchannel.o putoptv.o readpacket.o sendpacket.o todigit.o uintspec.o version.o
int6kbootp: int6kbootp.o BootDevice1.o BootFirmware1.o BootParameters1.o Confirm.o Devices.o Display.o EthernetHeader.o Failure.o FlashDevice3.o FlashPTS.o FlashPTS.o InitDevice1.o MMECode.o QualcommHeader.o ReadMME.o Request.o SendMME.o StartFirmware1.o UnwantedMessage.o WaitForRestart.o WaitForReset.o WaitForStart.o WriteExecuteFirmware1.o WriteExecutePIB.o WriteFirmware1.o WriteMEM.o WriteNVM.o WritePIB.o channel.o checkfilename.o checksum32.o chipset.o closechannel.o error.o fdchecksum32.o getoptv.o hexdecode.o hexencode.o hexdump.o hexstring.o keys.o lightning_nvm_file.o lightning_pib_file.o lightning_pib_peek.o openchannel.o putoptv.o readpacket.o sendpacket.o strfbits.o todigit.o typename.o uintspec.o version.o synonym.o
int6kecho: int6kecho.o Devices.o Display.o EthernetHeader.o Failure.o Loopback.o MMECode.o QualcommHeader.o ReadMME.o SendMME.o UnwantedMessage.o assist.o channel.o checkfilename.o checksum32.o closechannel.o error.o codelist.o fdchecksum32.o getoptv.o hexdecode.o hexdump.o hexencode.o hexload.o hexstring.o lookup.o openchannel.o putoptv.o readpacket.o sendpacket.o strfbits.o synonym.o todigit.o typename.o uintspec.o version.o
int6kfp: int6kfp.o Confirm.o Devices.o Display.o EthernetHeader.o Failure.o FlashDevice3.o FlashPTS.o HomePlugHeader.o MMECode.o QualcommHeader.o ReadMME.o Request.o SendMME.o StartDevice1.o StartFirmware1.o UnwantedMessage.o WaitForRestart.o WaitForReset.o WaitForStart.o WriteCFG.o WriteFirmware1.o WriteMEM.o WriteNVM.o WritePIB.o channel.o checkfilename.o checksum32.o chipset.o closechannel.o error.o fdchecksum32.o getoptv.o hexdecode.o hexdump.o hexencode.o hexstring.o keys.o lightning_nvm_file.o lightning_nvm_peek.o lightning_pib_file.o lightning_pib_peek.o nvm.o openchannel.o putoptv.o readpacket.o sdramfile.o sdrampeek.o sendpacket.o strfbits.o todigit.o typename.o uintspec.o version.o synonym.o
int6kp: int6kp.o Attributes1.o Confirm.o Devices.o Display.o EraseFlashMemory1.o EthernetHeader.o FactoryDefaults.o Failure.o FlashDevice3.o FlashPTS.o QualcommHeader1.o HostActionResponse.o Identity1.o MMECode.o NVRAMInfo.o NetInfo1.o PLCSelect.o PushButton.o QualcommHeader.o ReadFirmware1.o ReadFlashFirmware.o ReadFlashParameters.o ReadMFG.o ReadMME.o ReadParameters1.o Request.o ResetDevice.o SDRAMInfo.o SendMME.o SetNMK.o StationRole.o UnwantedMessage.o VersionInfo1.o WaitForRestart.o WaitForReset.o WaitForStart.o WatchdogReport.o WriteCFG.o WriteNVM.o WritePIB.o basespec.o channel.o checkfilename.o checksum32.o chipset.o closechannel.o error.o fdchecksum32.o getoptv.o hexdecode.o hexdump.o hexencode.o hexstring.o keys.o lightning_nvm_file.o nvram.o openchannel.o lightning_pib_file.o lightning_pib_peek.o putoptv.o readpacket.o sdramfile.o sdrampeek.o sendpacket.o strfbits.o synonym.o todigit.o typename.o uintspec.o version.o
int6kprobe: int6kprobe.o Confirm.o Devices.o Display.o EthernetHeader.o Failure.o MMECode.o NetworkProbe.o QualcommHeader.o ReadMME.o Request.o SendMME.o UnwantedMessage.o channel.o closechannel.o error.o getoptv.o hexdecode.o hexdump.o hexencode.o hexstring.o openchannel.o putoptv.o readpacket.o sendpacket.o synonym.o todigit.o uintspec.o version.o
plcecho: plcecho.o Devices.o Display.o EthernetHeader.o Failure.o Loopback.o MMECode.o QualcommHeader.o ReadMME.o SendMME.o UnwantedMessage.o assist.o channel.o checkfilename.o checksum32.o closechannel.o error.o codelist.o fdchecksum32.o getoptv.o hexdecode.o hexdump.o hexencode.o hexload.o hexstring.o lookup.o openchannel.o putoptv.o readpacket.o sendpacket.o strfbits.o synonym.o todigit.o typename.o uintspec.o version.o
plcinit: plcinit.o AccessLevelPTS.o Attributes2.o Confirm.o Devices.o Display.o EraseFlashMemory2.o EraseFlashSector.o EthernetHeader.o FactoryDefaults.o Failure.o FlashDevice2.o FlashFirmware.o FlashNVM.o FlashParameters.o FlashSoftloader.o QualcommHeader1.o HostActionResponse.o Identity2.o MMECode.o ModuleCommit.o ModuleErase.o ModuleRead.o ModuleSession.o ModuleSpec.o ModuleWrite.o NVRAMInfo.o NetInfo2.o PLCSelect.o PushButton.o QualcommHeader.o ReadFirmware1.o ReadFlashMemory2.o ReadMFG.o ReadMME.o ReadParameters2.o RemoteHosts.o Request.o ResetDevice.o SDRAMInfo.o SendMME.o SetNMK.o StartFirmware1.o StationRole.o UnwantedMessage.o VersionInfo2.o WaitForReset.o WaitForStart.o WatchdogReport.o WriteNVM.o WritePIB.o basespec.o channel.o checkfilename.o checksum32.o chipset.o closechannel.o error.o fdchecksum32.o getoptv.o hexdecode.o hexdump.o hexencode.o hexout.o hexstring.o keys.o panther_nvm_file.o nvram.o openchannel.o panther_pib_file.o panther_pib_peek.o putoptv.o readpacket.o sdramfile.o sdrampeek.o sendpacket.o strfbits.o synonym.o todigit.o typename.o uintspec.o version.o LinkStatus.o WaitForRestart.o 
plcmcinfo: plcmcinfo.o Confirm.o Devices.o Display.o EthernetHeader.o Failure.o QualcommHeader1.o MMECode.o MulticastInfo1.o MulticastInfo2.o QualcommHeader.o ReadFMI.o ReadMME.o Request.o SendMME.o UnwantedMessage.o basespec.o channel.o checksum32.o chipset.o closechannel.o decdecode.o decstring.o error.o getoptv.o hexdecode.o hexdump.o hexencode.o hexout.o hexstring.o nvram.o openchannel.o putoptv.o readpacket.o sdramfile.o sdrampeek.o sendpacket.o strfbits.o synonym.o todigit.o typename.o uintspec.o version.o
plcmod: plcmod.o AccessLevelPTS.o Confirm.o Devices.o Display.o EthernetHeader.o Failure.o keys.o MMECode.o ModuleCommit.o ModuleDump.o ModuleRead.o ModuleSession.o ModuleSpec.o ModuleWrite.o QualcommHeader.o ReadMME.o Request.o SendMME.o UnwantedMessage.o basespec.o channel.o checkfilename.o checksum32.o closechannel.o error.o fdchecksum32.o getoptv.o hexdecode.o hexdump.o hexencode.o hexstring.o hexview.o openchannel.o putoptv.o readpacket.o sendpacket.o strfbits.o synonym.o todigit.o typename.o uintspec.o version.o
plcsnif: plcsnif.o Confirm.o Devices.o Display.o EthernetHeader.o Failure.o MMECode.o Monitor.o QualcommHeader.o ReadMME.o Request.o SendMME.o Sniffer.o UnwantedMessage.o channel.o chipset.o closechannel.o error.o getoptv.o hexdecode.o hexdump.o hexencode.o hexout.o hexstring.o openchannel.o putoptv.o readpacket.o sendpacket.o synonym.o todigit.o typename.o uintspec.o version.o
psgen: psgen.o error.o fdchecksum32.o getoptv.o lookup.o lightning_pib_file.o lightning_pib_lock.o pibscalers.o psgen_util.o todigit.o putoptv.o version.o
solicit: solicit.o Request.o Confirm.o EthernetHeader.o Failure.o MMECode.o Request.o channel.o closechannel.o error.o getoptv.o hexdecode.o hexdump.o hexencode.o hexstring.o LLDP.o openchannel.o putoptv.o readpacket.o sendpacket.o synonym.o todigit.o uintspec.o version.o TLVPack.o TLVPackOS.o TLVPick.o TLVPeek.o decdecode.o decstring.o strfbits.o config.o memswap.o
respond: respond.o Request.o Confirm.o EthernetHeader.o channel.o closechannel.o error.o getoptv.o hexcopy.o hexdecode.o hexdump.o hexencode.o hexstring.o LLDP.o openchannel.o putoptv.o readpacket.o sendpacket.o todigit.o uintspec.o version.o TLVPack.o TLVPackOS.o TLVPick.o TLVPeek.o decdecode.o decstring.o strfbits.o synonym.o config.o memswap.o
psdump: psdump.o error.o fdchecksum32.o getoptv.o hexdecode.o hexstring.o putoptv.o todigit.o uintspec.o version.o

# ====================================================================
# includes;
# --------------------------------------------------------------------

include ../tools/tools.mak
include ../ether/ether.mak
include ../ram/ram.mak
include ../pib/pib.mak
include ../nvm/nvm.mak
include ../mme/mme.mak
include ../nda/nda.mak
include ../plc/plc.mak
include ../key/key.mak


