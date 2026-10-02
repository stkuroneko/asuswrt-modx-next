# ====================================================================
# programs;
# --------------------------------------------------------------------

add_executable(arpc arpc.c)
add_executable(ampinit ampinit.c)
add_executable(plcecho plcecho.c)
add_executable(plcinit plcinit.c)
add_executable(plcmcinfo plcmcinfo.c)
add_executable(plcmod plcmod.c)
add_executable(psgen psgen.c psgen_util.c)
add_executable(int6kecho int6kecho.c)
add_executable(int6kp int6kp.c)
add_executable(int6kprobe int6kprobe.c)

# ====================================================================
# libraries;
# --------------------------------------------------------------------

add_library(nda FlashPTS.c ReadFlashFirmware.c ReadFlashParameters.c EraseFlashMemory1.c EraseFlashMemory2.c ReadFlashMemory2.c Loopback.c NetworkProbe.c ModuleErase.c AccessLevelPTS.c EraseFlashSector.c MulticastInfo1.c MulticastInfo2.c Monitor.c Sniffer.c)

# ====================================================================
# dependencies;
# --------------------------------------------------------------------

target_link_libraries(ampinit plc nda mme ram pib nvm key ether tools)
target_link_libraries(arpc mme ether tools)
target_link_libraries(int6kecho nda plc mme ether tools)
target_link_libraries(int6kp plc nda key pib ram nvm mme ether tools)
target_link_libraries(int6kprobe nda plc mme ether tools)
target_link_libraries(plcecho nda plc mme ether tools)
target_link_libraries(plcinit plc nda mme ram pib nvm key ether tools)
target_link_libraries(plcmcinfo nda plc mme ether tools)
target_link_libraries(plcmod nda plc mme key ether tools)

if (WIN32)
	target_link_libraries(psgen pib tools)
else (WIN32)
	target_link_libraries(psgen pib tools m)
endif (WIN32)

