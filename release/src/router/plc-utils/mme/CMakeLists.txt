# ====================================================================
# programs
# --------------------------------------------------------------------

add_executable(hpav hpav.c)
# add_executable(mme mme.c)

# ====================================================================
# libraries;
# --------------------------------------------------------------------

add_library(mme MMECode.c MMEPeek.c MMEMode.c MMEName.c MMEShow.c EthernetHeader.c QualcommHeader.c UnwantedMessage.c FragmentHeader.c HomePlugHeader.c ARPCPrint.c ARPCWrite.c FirmwareMessage.c)

# ====================================================================
# dependencies;
# --------------------------------------------------------------------

target_link_libraries(hpav mme)

if (WIN32)
target_link_libraries(mme plc ws2_32)
else (WIN32)
target_link_libraries(mme plc)
endif (WIN32)

