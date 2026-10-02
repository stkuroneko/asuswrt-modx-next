# ====================================================================
# definitions;
# --------------------------------------------------------------------

add_definitions(-DAR7x00)

# ====================================================================
# programs;
# --------------------------------------------------------------------

add_executable(ampboot ampboot.c)
add_executable(CMEncrypt CMEncrypt.c)
add_executable(ampID ampID.c)
add_executable(int6k int6k.c)
add_executable(int6kboot int6kboot.c)
add_executable(int6keth int6keth.c)
add_executable(int6khost int6khost.c)
add_executable(int64host int64host.c)
add_executable(int6kid int6kid.c)
add_executable(int6klist int6klist.c)
add_executable(int6klog int6klog.c)
add_executable(int6kmdio int6kmdio.c)
add_executable(int6kmdio2 int6kmdio2.c)
add_executable(int6kmod int6kmod.c)
add_executable(int6kstat int6kstat.c)
add_executable(int6ktest int6ktest.c)
add_executable(int6krate int6krate.c)
add_executable(int6krule int6krule.c)
add_executable(int6ktone int6ktone.c)
add_executable(int6kwait int6kwait.c)
add_executable(sada sada.c)
add_executable(coqos_add coqos_add.c)
add_executable(coqos_info coqos_info.c)
add_executable(coqos_man coqos_man.c)
add_executable(coqos_mod coqos_mod.c)
add_executable(coqos_rel coqos_rel.c)
add_executable(mdustats mdustats.c)
add_executable(amphost amphost.c)
add_executable(amplist amplist.c)
add_executable(amprate amprate.c)
add_executable(ampstat ampstat.c)
add_executable(amptest amptest.c)
add_executable(amptool amptool.c)
add_executable(amptone amptone.c)
add_executable(ampwait ampwait.c)
add_executable(plcboot plcboot.c)
add_executable(plchost plchost.c)
add_executable(plcID plcID.c)
add_executable(plclist plclist.c)
add_executable(plcrate plcrate.c)
add_executable(plcrule plcrule.c)
add_executable(plcstat plcstat.c)
add_executable(plctest plctest.c)
add_executable(plctool plctool.c)
add_executable(plctone plctone.c)
add_executable(plcwait plcwait.c)
add_executable(plcget plcget.c)
add_executable(plcset plcset.c)
add_executable(plcotst plcotst.c)
add_executable(plcfwd plcfwd.c)
add_executable(plcmdio16 plcmdio16.c)
add_executable(plcmdio32 plcmdio32.c)

if (NOT WIN32)
	add_executable(plchostd plchostd.c)
	add_executable(plcdevs plcdevs.c)
endif (NOT WIN32)

# ====================================================================
# libraries;
# --------------------------------------------------------------------

add_library(plc
	ParseRule.c
	rules.c
	VersionInfo1.c
	Attributes1.c
	Identity1.c
	SendMME.c
	ReadMME.c
	Failure.c
	Confirm.c
	WatchdogReport.c
	Request.c
	Display.c
	Devices.c
	chipset.c
	WriteNVM.c
	WritePIB.c
	HostActionResponse.c
	FactoryReset.c
	FactoryDefaults.c
	ResetDevice.c
	SDRAMInfo.c
	RemoteHosts.c
	SetNMK.c
	PushButton.c
	NetInfo1.c
	NetInfo2.c
	ReadMFG.c
	NVRAMInfo.c
	StationRole.c
	WriteCFG.c
	ModuleRead.c
	ModuleCommit.c
	ModuleSession.c
	VersionInfo2.c
	Attributes2.c
	Identity2.c
	FlashDevice2.c
	FlashFirmware.c
	FlashParameters.c
	FlashSoftloader.c
	ModuleSpec.c
	ModuleWrite.c
	ReadFMI.c
	ModuleDump.c
	WaitForStart.c
	InitDevice.c
	InitDevice1.c
	InitDevice2.c
	BootDevice1.c
	BootDevice2.c
	FlashDevice1.c
	WaitForReset.c
	FlashNVM.c
	BootFirmware1.c
	BootFirmware2.c
	StartFirmware1.c
	WriteFirmware1.c
	WriteExecuteFirmware1.c
	WriteExecuteFirmware2.c
	WriteExecuteParameters1.c
	WriteExecuteParameters2.c
	BootParameters1.c
	BootParameters2.c
	WriteMEM.c
	WriteExecutePIB.c
	WriteMOD.c
	ReadParameterBlock.c
	LocalDevices.c
	DeviceIdent.c
	ChangeIdent.c
	ReadFirmware1.c
	ReadFirmware2.c
	ReadParameters.c
	ReadParameters1.c
	ReadParameters2.c
	EmulateHost.c
	EmulateHost64.c
	ListLocalDevices.c
	ListRemoteDevices.c
	ListRemoteDevices1.c
	ListRemoteDevices2.c
	Transmit.c
	Traffic1.c
	Traffic2.c
	NetworkTraffic1.c
	NetworkTraffic2.c
	Antiphon.c
	PhyRates1.c
	PhyRates2.c
	RxRates2.c
	Topology1.c
	Topology2.c
	PLCTopology.c
	PLCTopologyPrint.c
	NetworkInformation1.c
	NetworkInformation2.c
	LinkStatistics.c
	LinkStatus.c
	Platform.c
	ExecuteApplets.c
	ExecuteApplets1.c
	ExecuteApplets2.c
	WriteExecuteApplet2.c
	SignalToNoise1.c
	SignalToNoise2.c
	ToneMaps1.c
	ToneMaps2.c
	MDUTrafficStats.c
	GetProperty.c
	SetProperty.c
	PLCSelect.c
	NVMSelect.c
	SlaveMembership.c
	)

# ====================================================================
# dependencies;
# --------------------------------------------------------------------

target_link_libraries(CMEncrypt plc key)
target_link_libraries(ampID plc)
target_link_libraries(ampboot plc)
target_link_libraries(int6k key plc)
target_link_libraries(int6kboot plc)
target_link_libraries(int6keth plc)
target_link_libraries(int6khost plc)
target_link_libraries(int64host plc)
target_link_libraries(int6kid plc)
target_link_libraries(int6klist plc)
target_link_libraries(int6klog plc)
target_link_libraries(int6kmdio plc)
target_link_libraries(int6kmdio2 plc)
target_link_libraries(int6kmod plc)
target_link_libraries(int6kstat plc)
target_link_libraries(int6ktest plc)
target_link_libraries(int6krate plc)
target_link_libraries(int6krule plc)
target_link_libraries(int6ktone plc)
target_link_libraries(int6kwait plc)
target_link_libraries(sada plc)
target_link_libraries(coqos_add plc)
target_link_libraries(coqos_info plc)
target_link_libraries(coqos_man plc)
target_link_libraries(coqos_mod plc)
target_link_libraries(coqos_rel plc)
target_link_libraries(mdustats plc)
target_link_libraries(amphost plc)
target_link_libraries(amplist plc)
target_link_libraries(amprate plc)
target_link_libraries(ampstat plc)
target_link_libraries(amptest plc)
target_link_libraries(amptool plc key)
target_link_libraries(amptone plc)
target_link_libraries(ampwait plc)
target_link_libraries(plc ram nvm pib mme ether tools)
target_link_libraries(plcboot plc)
target_link_libraries(plchost plc)
target_link_libraries(plcID plc)
target_link_libraries(plclist plc)
target_link_libraries(plcrate plc)
target_link_libraries(plcrule plc)
target_link_libraries(plcstat plc)
target_link_libraries(plctest plc)
target_link_libraries(plctool plc key)
target_link_libraries(plctone plc)
target_link_libraries(plcwait plc)
target_link_libraries(plcget plc)
target_link_libraries(plcset plc)
target_link_libraries(plcotst plc)
target_link_libraries(plcfwd plc)
target_link_libraries(plcmdio16 plc)
target_link_libraries(plcmdio32 plc)

if (NOT WIN32)
target_link_libraries(plchostd plc)
target_link_libraries(plcdevs plc)
endif (NOT WIN32)


