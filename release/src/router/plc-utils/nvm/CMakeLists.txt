# ====================================================================
# programs
# --------------------------------------------------------------------

add_executable(chknvm chknvm.c)
add_executable(chknvm2 chknvm2.c)
add_executable(nvmsplit nvmsplit.c)
add_executable(nvmmerge nvmmerge.c)

# ====================================================================
# dependencies
# --------------------------------------------------------------------

target_link_libraries(chknvm nvm ram tools)
target_link_libraries(chknvm2 nvm tools)
target_link_libraries(nvmmerge nvm tools)
target_link_libraries(nvmsplit nvm tools)

# ====================================================================
# libraries
# --------------------------------------------------------------------

add_library(nvm manifest.c manifetch.c nvmfile.c nvmfile1.c nvmfile2.c nvmpeek1.c nvmpeek2.c nvm.c nvmseek1.c nvmseek2.c fdmanifest.c)

