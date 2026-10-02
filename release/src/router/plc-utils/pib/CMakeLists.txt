# ====================================================================
# programs;
# --------------------------------------------------------------------

add_executable(chkpib chkpib.c)
add_executable(chkpib2 chkpib2.c)
add_executable(setpib setpib.c)
add_executable(getpib getpib.c)
add_executable(modpib modpib.c)
add_executable(pib2xml pib2xml.c)
add_executable(pibcomp pibcomp.c)
add_executable(pibdump pibdump.c)
add_executable(xml2pib xml2pib.c)
add_executable(psin psin.c)
add_executable(psout psout.c)
add_executable(pskey pskey.c)
add_executable(pibrump pibrump.c)

# ====================================================================
# dependencies;
# --------------------------------------------------------------------

target_link_libraries(chkpib pib key nvm tools)
target_link_libraries(chkpib2 pib key nvm tools)
target_link_libraries(getpib pib nvm tools)
target_link_libraries(modpib pib key tools)
target_link_libraries(pibcomp pib nvm tools)
target_link_libraries(pibdump nvm tools)
target_link_libraries(pib2xml nvm nodes tools)
target_link_libraries(psin pib tools)
target_link_libraries(psout pib tools)
target_link_libraries(pskey pib key tools)
target_link_libraries(setpib nvm tools)
target_link_libraries(xml2pib nodes tools)
target_link_libraries(pibrump pib plc tools)

# ====================================================================
# libraries;
# --------------------------------------------------------------------

add_library(pib pibfile.c lightning_pib_file.c lightning_pib_lock.c lightning_pib_peek.c lightning_pib_size.c panther_pib_file.c.c panther_pib_peek.c panther_pib_size.c pibscalers.c)

